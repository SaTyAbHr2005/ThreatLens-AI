"""Free LLM router: one call, many free providers, automatic fallback.

Groq, Gemini, OpenRouter and Ollama all expose an OpenAI-compatible
`/chat/completions` endpoint, so one small HTTP client covers all of them; no
provider SDKs needed.

Detection never calls this module. It is used for simulated agents, alert
narratives, contract drafting and the arena, all of which have non-LLM
fallbacks, so `LLMUnavailable` is an expected outcome callers must handle.
"""

import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import Settings, get_settings

GROQ_URL = "https://api.groq.com/openai/v1"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/openai"
OPENROUTER_URL = "https://openrouter.ai/api/v1"

# Provider families tried in order for each task.
TASK_CHAINS: dict[str, list[str]] = {
    "agent": ["groq", "gemini", "openrouter", "ollama"],
    "narrative": ["gemini", "groq", "openrouter", "ollama"],
    "draft_contract": ["gemini", "groq", "openrouter", "ollama"],
    "classify": ["groq", "gemini", "openrouter", "ollama"],
}

RATE_LIMIT_COOLDOWN_S = 30.0
ERROR_COOLDOWN_S = 10.0


class LLMUnavailable(Exception):
    """Every provider in the chain failed or is cooling down."""


class LLMRateLimited(LLMUnavailable):
    """One named provider answered 429. `retry_after` is how long it asked us to wait."""

    def __init__(self, message: str, retry_after: float):
        super().__init__(message)
        self.retry_after = retry_after


@dataclass
class Provider:
    name: str  # e.g. "groq" or "openrouter:<model>"
    family: str  # groq | gemini | openrouter | ollama
    base_url: str
    api_key: str
    model: str
    cooldown_until: float = 0.0
    last_error: str | None = None

    def ready(self, now: float) -> bool:
        return now >= self.cooldown_until


@dataclass
class LLMResult:
    text: str | None
    provider: str
    model: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


class _RateLimited(Exception):
    def __init__(self, retry_after: float, detail: str = ""):
        self.retry_after = retry_after
        self.detail = detail


def providers_from_settings(s: Settings) -> list[Provider]:
    out: list[Provider] = []
    if s.groq_api_key:
        out.append(Provider("groq", "groq", GROQ_URL, s.groq_api_key, s.groq_model))
    if s.gemini_api_key:
        out.append(Provider("gemini", "gemini", GEMINI_URL, s.gemini_api_key, s.gemini_model))
    if s.openrouter_api_key:
        for m in s.openrouter_model_list:
            out.append(Provider(f"openrouter:{m}", "openrouter", OPENROUTER_URL, s.openrouter_api_key, m))
    if s.ollama_url:
        out.append(Provider("ollama", "ollama", f"{s.ollama_url.rstrip('/')}/v1", "ollama", s.ollama_model))
    return out


class LLMRouter:
    def __init__(
        self,
        providers: list[Provider],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_s: float = 30.0,
        cache_size: int = 256,
    ) -> None:
        self.providers = providers
        self._client = httpx.AsyncClient(transport=transport, timeout=timeout_s)
        self._cache: OrderedDict[str, LLMResult] = OrderedDict()
        self._cache_size = cache_size

    @classmethod
    def from_settings(cls, settings: Settings | None = None, **kw: Any) -> "LLMRouter":
        return cls(providers_from_settings(settings or get_settings()), **kw)

    def chain(self, task: str) -> list[Provider]:
        families = TASK_CHAINS[task]
        return sorted(
            (p for p in self.providers if p.family in families),
            key=lambda p: families.index(p.family),
        )

    async def complete(
        self,
        task: str,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 512,
        cache: bool = False,
    ) -> LLMResult:
        """Try each provider for `task` in order. Raises LLMUnavailable if all fail."""
        key = _cache_key(task, messages, tools) if cache else None
        if key and key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]

        now = time.monotonic()
        tried: list[str] = []
        for p in self.chain(task):
            if not p.ready(now):
                tried.append(f"{p.name}: cooling down")
                continue
            try:
                result = await self._call(p, messages, tools, temperature, max_tokens)
            except _RateLimited as e:
                p.cooldown_until = time.monotonic() + e.retry_after
                p.last_error = "rate limited"
            except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
                p.cooldown_until = time.monotonic() + ERROR_COOLDOWN_S
                p.last_error = type(e).__name__
            else:
                p.last_error = None
                if key:
                    self._cache[key] = result
                    if len(self._cache) > self._cache_size:
                        self._cache.popitem(last=False)
                return result
            tried.append(f"{p.name}: {p.last_error}")
        raise LLMUnavailable("; ".join(tried) or f"no provider configured for task {task!r}")

    async def complete_with(self, provider_name: str, messages: list[dict[str, Any]], **kw: Any) -> LLMResult:
        """Call one named provider directly (used by the LLM Susceptibility Arena).

        `timeout` overrides the client's per-request timeout for this call.
        """
        p = next((p for p in self.providers if p.name == provider_name), None)
        if p is None:
            raise LLMUnavailable(f"unknown provider {provider_name!r}")
        try:
            return await self._call(
                p, messages, kw.get("tools"), kw.get("temperature", 0.2), kw.get("max_tokens", 512), kw.get("timeout")
            )
        except _RateLimited as e:
            why = f" ({e.detail})" if e.detail else ""
            raise LLMRateLimited(f"rate limited{why}, retry in {e.retry_after:.0f} s", e.retry_after) from e  # caller knows which provider

    def status(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        return [
            {
                "provider": p.name,
                "model": p.model,
                "ready": p.ready(now),
                "cooldown_s": max(0.0, round(p.cooldown_until - now, 1)),
                "last_error": p.last_error,
            }
            for p in self.providers
        ]

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _call(
        self,
        p: Provider,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        temperature: float,
        max_tokens: int,
        timeout: float | None = None,
    ) -> LLMResult:
        body: dict[str, Any] = {
            "model": p.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools
        r = await self._client.post(
            f"{p.base_url}/chat/completions",
            json=body,
            headers={"Authorization": f"Bearer {p.api_key}"},
            timeout=httpx.USE_CLIENT_DEFAULT if timeout is None else timeout,
        )
        if r.status_code == 429:
            raise _RateLimited(_retry_after(r), _error_message(r))
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        return LLMResult(
            text=msg.get("content"),
            provider=p.name,
            model=p.model,
            tool_calls=msg.get("tool_calls") or [],
        )


def _retry_after(r: httpx.Response) -> float:
    try:
        return float(r.headers.get("retry-after", RATE_LIMIT_COOLDOWN_S))
    except ValueError:
        return RATE_LIMIT_COOLDOWN_S


def _error_message(r: httpx.Response) -> str:
    """The provider's own reason, e.g. OpenRouter's daily free-model cap or an upstream rate limit."""
    try:
        err = r.json().get("error") or {}
        msg = str((err.get("metadata") or {}).get("raw") or err.get("message") or "")
        return msg.split(". ")[0][:160]  # first sentence; the rest is advice and links
    except (ValueError, AttributeError):
        return ""


def _cache_key(task: str, messages: list[dict[str, Any]], tools: Any) -> str:
    raw = json.dumps([task, messages, tools], sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()
