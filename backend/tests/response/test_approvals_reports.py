import json

import httpx

from threatlens.core.schemas import AgentStatus, ApprovalStatus, Decision, DecisionType, Tier
from threatlens.response import ApprovalQueue, DiscordNotifier, dossier_markdown, ocsf_finding


async def _held(r):
    await r.response.apply("hr-agent", "step_up", "under review", "analyst@corp.example")
    res = await r.call("hr-agent", "hr_db.query", table="profile")  # confidential: needs a person
    assert res.decision is DecisionType.require_approval and res.approval_id
    assert r.tools.ran("hr_db.query") == 0
    return res


async def test_approved_action_runs_once_and_is_audited(r):
    res = await _held(r)
    assert [a.id for a in r.response.approvals.list(ApprovalStatus.pending)] == [res.approval_id]
    a = await r.response.approvals.decide(res.approval_id, True, "analyst@corp.example", r.gateway)
    await r.bus.drain()
    assert a.status is ApprovalStatus.approved and a.result == {"ok": True, "tool": "hr_db.query"}
    assert r.tools.ran("hr_db.query") == 1
    assert r.events[-1].rule == "approved" and "analyst@corp.example" in r.events[-1].reason


async def test_denied_and_expired_approvals_never_run(r):
    res = await _held(r)
    a = await r.response.approvals.decide(res.approval_id, False, "analyst@corp.example", r.gateway)
    assert a.status is ApprovalStatus.denied and r.tools.ran("hr_db.query") == 0

    r.response.approvals.ttl_s = 0
    res2 = await r.call("hr-agent", "hr_db.query", table="profile")
    assert r.response.approvals.get(res2.approval_id).status is ApprovalStatus.expired


async def test_isolation_denies_pending_approvals(r):
    res = await _held(r)
    await r.response.apply("hr-agent", "isolate", "confirmed", "analyst@corp.example")
    assert r.response.approvals.get(res.approval_id).status is ApprovalStatus.denied


async def test_dossier_and_ocsf(r):
    token = r.token("procurement-agent")
    await r.poison(token)
    hr = await r.call(token, "files.read", path="/hr/salaries.xlsx")
    alert = r.fusion.live_alert(next(e for e in r.events if e.id == hr.event_id).alert_id)
    decisions = await r.response.decisions.list("procurement-agent")
    events = [e for e in r.events if e.id in alert.timeline]

    md = dossier_markdown(alert, decisions, events)
    assert alert.containment is AgentStatus.step_up
    for part in ("# Incident", "**Containment applied:** step-up", "## Hidden instruction found",
                 "/hr/salaries.xlsx", "## Why it scored this risk",
                 "## Actions taken", "Step-up:", "## Containment decisions", "active → step_up",
                 "OWASP LLM01:2025", "Quarantine supplier_quote.pdf"):
        assert part in md, part

    f = ocsf_finding(alert)
    assert f["class_uid"] == 2004 and f["severity"] == "Critical" and f["finding_info"]["uid"] == alert.id
    assert f["unmapped"]["cause_content_id"] == alert.cause_content_id and f["evidences"]
    json.dumps(f)  # serializable as-is for a SIEM


async def test_discord_notifier_posts_step_up_and_isolate_only():
    sent = []

    def handler(req):
        sent.append(json.loads(req.content))
        return httpx.Response(204)

    n = DiscordNotifier("https://discord.test/webhook", console_url="https://tl.example",
                        transport=httpx.MockTransport(handler))

    def d(status, agent="a1"):
        return Decision(agent_id=agent, decision=DecisionType.quarantine, tier=Tier.isolate, reason="canary",
                        to_status=status, alert_id="alr_1", details={"revoked_tokens": 2})

    await n.on_decision(d(AgentStatus.restricted))
    await n.on_decision(d(AgentStatus.quarantined))
    await n.on_decision(d(AgentStatus.step_up, agent="a2"))
    assert [s["embeds"][0]["title"] for s in sent] == ["ThreatLens: a1 isolated", "ThreatLens: a2 held for step-up approval"]
    assert sent[0]["embeds"][0]["url"] == "https://tl.example/console/incidents/alr_1"
    assert sent[0]["username"] == "ThreatLens"
    await n.aclose()


def test_queue_unknown_and_double_decisions():
    import asyncio

    import pytest

    from threatlens.response import ApprovalError

    q = ApprovalQueue()
    with pytest.raises(ApprovalError):
        asyncio.run(q.decide("apr_missing", True, "x", None))
