"""Llama Prompt Guard 2 via Groq's free API (returns a probability as text).

Runs off-box, so it costs none of Render's 512 MB. Good at classic jailbreaks;
blind to indirect instructions that read like normal tasks, which is why it is
combined with heuristics.py and, above all, with behavior (M4).
"""

import hashlib
import time
from collections import OrderedDict

import httpx

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
CHUNK = 2000  # characters; the model sees ~512 tokens
MAX_CHUNKS = 6


class PromptGuardUnavailable(Exception):
    pass


class PromptGuard:
    def __init__(self, api_key: str, model: str, *, transport: httpx.AsyncBaseTransport | None = None,
                 timeout_s: float = 10.0, cache_size: int = 2048):
        self.model = model
        self._key = api_key
        self._client = httpx.AsyncClient(transport=transport, timeout=timeout_s)
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._cache_size = cache_size
        self._cooldown_until = 0.0

    async def score(self, text: str) -> float:
        """Max probability over the first few chunks. Raises PromptGuardUnavailable."""
        chunks = [text[i:i + CHUNK] for i in range(0, len(text), CHUNK)][:MAX_CHUNKS]
        best = 0.0
        for chunk in chunks:
            if chunk.strip():
                best = max(best, await self._score_chunk(chunk))
        return best

    async def _score_chunk(self, chunk: str) -> float:
        key = hashlib.sha256(chunk.encode()).hexdigest()
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        if time.monotonic() < self._cooldown_until:
            raise PromptGuardUnavailable("rate limited")
        try:
            r = await self._client.post(
                GROQ_URL,
                headers={"Authorization": f"Bearer {self._key}"},
                json={"model": self.model, "messages": [{"role": "user", "content": chunk}]},
            )
        except httpx.HTTPError as e:
            raise PromptGuardUnavailable(type(e).__name__) from e
        if r.status_code == 429:
            self._cooldown_until = time.monotonic() + float(r.headers.get("retry-after", 30) or 30)
            raise PromptGuardUnavailable("rate limited")
        if r.status_code != 200:
            raise PromptGuardUnavailable(f"HTTP {r.status_code}")
        try:
            value = float(r.json()["choices"][0]["message"]["content"].strip())
        except (KeyError, IndexError, ValueError, TypeError, AttributeError) as e:
            raise PromptGuardUnavailable("unexpected response") from e
        value = max(0.0, min(1.0, value))
        self._cache[key] = value
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return value

    async def aclose(self) -> None:
        await self._client.aclose()
