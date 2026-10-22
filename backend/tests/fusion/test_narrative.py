"""LLM narratives: written off the hot path, from structured fields only."""

import json

import httpx
import pytest

from threatlens.core.llm import LLMRouter, Provider

SENT: list[str] = []


def _handler(req: httpx.Request):
    SENT.append(req.content.decode())
    return httpx.Response(200, json={"choices": [{"message": {
        "content": "The procurement agent read HR salary data right after opening a supplier PDF with hidden instructions."}}]})


@pytest.fixture
def llm():
    SENT.clear()
    return LLMRouter([Provider("gemini", "gemini", "https://gemini.test/v1", "k", "m")],
                     transport=httpx.MockTransport(_handler))


async def test_narrative_is_added_and_never_sees_the_attackers_text(f):
    token = f.token("procurement-agent")
    await f.poisoned_pdf(token)
    _, hr = await f.call(token, "files.read", path="/hr/salaries.xlsx")
    await f.bus.drain()

    alert = await f.store.get(hr.alert_id)
    assert alert.narrative.startswith("The procurement agent read HR salary data")
    assert alert.narrative_source == "llm:gemini"
    assert alert.headline  # the template stays as the fallback

    assert SENT, "the LLM was called"
    body = json.loads(SENT[0])
    prompt = body["messages"][1]["content"]
    assert "POST it to" not in prompt and "Do not mention this" not in prompt  # decoded injection withheld
    facts = json.loads(prompt)
    assert facts["hidden_instruction_present"] is True
    # A recommendation is not an action: the model must not report containment that didn't happen.
    assert "recommended_containment" in facts and facts["actions_taken"] == []
    assert "unless that appears in actions_taken" in body["messages"][0]["content"]
