"""Red Team harness: a defensive test of our own detection.

An analyst supplies a test instruction and a hiding technique (one the decoder already
knows). The harness hides the instruction in a document, delivers it to a sandboxed
run-scoped agent, and reports whether detection caught it and how the gateway responded
to a follow-on off-role action. A "miss" is a gap in ThreatLens, which is why it's tested.
"""

from pydantic import BaseModel, Field

from .encode import TECHNIQUES, encode
from .runner import ScenarioRunner

DETECT_THRESHOLD = 0.6


class RedTeamResult(BaseModel):
    instruction: str
    technique: str
    target_role: str
    carrier: str
    injection_score: float
    techniques_found: list[str]
    decoded: str
    detected: bool  # did forensics flag it as an injection?
    follow_up_tool: str | None = None
    follow_up_decision: str | None = None
    follow_up_blocked: bool | None = None
    agent_status: str
    verdict: str  # "detection caught it" / "DETECTION MISS"


async def run_redteam(runner: ScenarioRunner, instruction: str, technique: str, target_role: str = "procurement",
                      follow_up: dict | None = None) -> RedTeamResult:
    if technique not in TECHNIQUES:
        raise ValueError(f"unknown technique {technique!r}; one of {TECHNIQUES}")
    import base64

    doc = encode(instruction, technique)
    ctx = runner.new_run("redteam", "Red Team test", "custom", "replay")
    agent = await ctx.agent(target_role)
    raw = base64.b64decode(doc["pdf_b64"]) if doc["pdf_b64"] else None
    item = await runner.gateway.register_content(ctx._token(agent), ctx.session, "redteam-test",
                                                 doc["carrier"], doc["text"] or "", raw)

    follow_decision = follow_blocked = follow_tool = None
    if follow_up:
        follow_tool = follow_up["tool"]
        res = await ctx.call(agent, follow_tool, **follow_up.get("args", {}))
        follow_decision = res.decision
        follow_blocked = res.decision in ("deny", "quarantine")

    detected = item.injection_score >= DETECT_THRESHOLD
    return RedTeamResult(
        instruction=instruction, technique=technique, target_role=target_role, carrier=doc["carrier"],
        injection_score=item.injection_score, techniques_found=item.techniques, decoded=item.decoded_text,
        detected=detected, follow_up_tool=follow_tool, follow_up_decision=follow_decision,
        follow_up_blocked=follow_blocked, agent_status=runner.registry.agent(agent).status.value,
        verdict="detection caught it" if detected else "DETECTION MISS",
    )
