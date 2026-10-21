import httpx
import pytest

from threatlens.core.config import Settings
from threatlens.core.llm import LLMRouter, LLMUnavailable, Provider, providers_from_settings


def _ok(text="hi", tool_calls=None):
    msg = {"role": "assistant", "content": text}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return httpx.Response(200, json={"choices": [{"message": msg}]})


def _router(handler, *families):
    providers = [Provider(f, f, f"https://{f}.test/v1", "key", f"{f}-model") for f in families]
    return LLMRouter(providers, transport=httpx.MockTransport(handler))


async def test_falls_back_when_first_provider_is_rate_limited():
    calls: list[str] = []

    def handler(req: httpx.Request):
        calls.append(req.url.host)
        if req.url.host == "groq.test":
            return httpx.Response(429, headers={"retry-after": "120"})
        return _ok("from gemini")

    r = _router(handler, "groq", "gemini")
    res = await r.complete("agent", [{"role": "user", "content": "x"}])
    assert res.text == "from gemini" and res.provider == "gemini"

    # groq is now cooling down, so the next call skips it entirely
    await r.complete("agent", [{"role": "user", "content": "y"}])
    assert calls == ["groq.test", "gemini.test", "gemini.test"]
    assert next(s for s in r.status() if s["provider"] == "groq")["ready"] is False


async def test_task_chain_order_differs_by_task():
    r = _router(lambda req: _ok(req.url.host), "groq", "gemini")
    assert (await r.complete("agent", [])).provider == "groq"
    assert (await r.complete("narrative", [])).provider == "gemini"


async def test_all_failing_raises_unavailable():
    r = _router(lambda req: httpx.Response(500), "groq", "gemini")
    with pytest.raises(LLMUnavailable):
        await r.complete("agent", [])


async def test_no_providers_raises_unavailable():
    with pytest.raises(LLMUnavailable):
        await LLMRouter([]).complete("narrative", [])


async def test_cache_avoids_second_call():
    calls = 0

    def handler(req):
        nonlocal calls
        calls += 1
        return _ok("cached")

    r = _router(handler, "gemini")
    msgs = [{"role": "user", "content": "same"}]
    await r.complete("narrative", msgs, cache=True)
    await r.complete("narrative", msgs, cache=True)
    assert calls == 1


async def test_tool_calls_are_returned():
    call = {"id": "c1", "type": "function", "function": {"name": "files.read", "arguments": "{}"}}
    r = _router(lambda req: _ok(None, [call]), "groq")
    res = await r.complete("agent", [], tools=[{"type": "function", "function": {"name": "files.read"}}])
    assert res.tool_calls == [call]


def test_providers_built_only_for_configured_keys():
    s = Settings(env="test", groq_api_key="g", openrouter_api_key="o", openrouter_models="a/free, b/free")
    names = [p.name for p in providers_from_settings(s)]
    assert names == ["groq", "openrouter:a/free", "openrouter:b/free"]
