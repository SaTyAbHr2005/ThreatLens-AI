from datetime import timedelta

import pytest

from threatlens.core.config import Settings
from threatlens.core.schemas import AgentStatus, utcnow
from threatlens.identity import (
    AgentExists,
    AgentQuarantined,
    DelegationDenied,
    InvalidAmendment,
    MemoryRegistryStore,
    Registry,
    TokenRevoked,
    UnknownRole,
)

S = Settings(env="test", jwt_signing_key="registry-test-key-0123456789-0123456789")

B1_CHANGE = {
    "allowed_tools": {"add": ["logistics_api.track"]},
    "prototype_actions": {"add": ["track shipment status for an open purchase order"]},
}


async def fresh(store=None) -> Registry:
    reg = Registry(store or MemoryRegistryStore(), S)
    await reg.load()
    return reg


@pytest.fixture
async def reg() -> Registry:
    r = await fresh()
    for agent_id, role in [
        ("procurement-agent", "procurement"),
        ("hr-agent", "hr"),
        ("finance-agent", "finance"),
        ("support-agent", "support"),
    ]:
        await r.create_agent(agent_id, role, f"{role}-team@corp.example")
    return r


# ---------------------------------------------------------------- agents & tokens


async def test_seeds_roles_from_yaml():
    reg = await fresh()
    assert [c.role for c in reg.roles()] == ["finance", "hr", "procurement", "support"]


async def test_token_is_scoped_to_the_role_contract(reg):
    issued = reg.issue_token("procurement-agent")
    claims = reg.verify(issued.token)
    assert claims.agent_id == "procurement-agent"
    assert claims.scopes == reg.contract("procurement").allowed_tools
    assert claims.chain == ["procurement-agent"] and claims.depth == 0
    assert claims.root_role == "procurement" and claims.act is None


async def test_create_agent_validation(reg):
    with pytest.raises(ValueError):
        await reg.create_agent("Bad Id!", "procurement", "x@corp.example")
    with pytest.raises(UnknownRole):
        await reg.create_agent("ghost-agent", "astronaut", "x@corp.example")
    with pytest.raises(AgentExists):
        await reg.create_agent("hr-agent", "hr", "x@corp.example")


async def test_revoked_token_fails_verification(reg):
    issued = reg.issue_token("hr-agent")
    await reg.revoke(issued.claims.jti, issued.claims.expires_at)
    with pytest.raises(TokenRevoked):
        reg.verify(issued.token)


async def test_quarantined_agent_gets_no_tokens(reg):
    await reg.set_status("hr-agent", AgentStatus.quarantined, drift=95)
    with pytest.raises(AgentQuarantined):
        reg.issue_token("hr-agent")
    assert reg.agent("hr-agent").trust == 5


async def test_refresh_root_but_not_delegated(reg):
    root = reg.issue_token("procurement-agent")
    again = reg.refresh(root.token)
    assert again.claims.jti != root.claims.jti
    child = reg.delegate(root.claims, "finance-agent")
    with pytest.raises(DelegationDenied):
        reg.refresh(child.token)


# ---------------------------------------------------------------- amendments (scenario B1)


async def test_signed_amendment_creates_next_version(reg):
    amd = await reg.amend("procurement", B1_CHANGE, "Track shipments for open POs", "lead@corp.example")
    assert (amd.from_version, amd.to_version) == (1, 2)
    assert amd.signature
    current = reg.contract("procurement")
    assert current.version == 2 and "logistics_api.track" in current.allowed_tools
    # New tokens pick up the new contract.
    assert "logistics_api.track" in reg.issue_token("procurement-agent").claims.scopes


@pytest.mark.parametrize("signer", ["procurement-agent", "not-an-email", ""])
async def test_amendment_needs_a_human_signer(reg, signer):
    with pytest.raises(InvalidAmendment):
        await reg.amend("procurement", B1_CHANGE, "reason", signer)


async def test_expired_amendment_stops_applying(reg):
    await reg.amend("procurement", B1_CHANGE, "temporary pilot", "lead@corp.example",
                    expires_at=utcnow() - timedelta(seconds=1))
    assert reg.contract("procurement").version == 1
    assert reg.contract("procurement", 2).version == 2  # still on record


# ---------------------------------------------------------------- delegation (scenario A4)


async def test_delegation_attenuates_scopes(reg):
    caller = reg.issue_token("procurement-agent").claims
    child = reg.delegate(caller, "finance-agent")
    claims = reg.verify(child.token)
    # finance tools ∩ procurement tools
    assert claims.scopes == ["files.read", "email.send"]
    assert claims.chain == ["procurement-agent", "finance-agent"] and claims.depth == 1
    assert claims.root_role == "procurement"
    assert claims.act == {"sub": "procurement-agent"}
    assert claims.expires_at <= caller.expires_at


async def test_delegation_outside_contract_is_denied(reg):
    with pytest.raises(DelegationDenied):
        reg.delegate(reg.issue_token("hr-agent").claims, "finance-agent")
    with pytest.raises(DelegationDenied):
        reg.delegate(reg.issue_token("finance-agent").claims, "procurement-agent")


async def test_delegation_cycle_is_denied(reg):
    await reg.amend("finance", {"delegation": {"may_call": ["procurement-agent"], "max_depth": 2}},
                    "test cycle", "lead@corp.example")
    child = reg.delegate(reg.issue_token("procurement-agent").claims, "finance-agent")
    with pytest.raises(DelegationDenied, match="cycle"):
        reg.delegate(child.claims, "procurement-agent")


async def test_cannot_delegate_to_quarantined_agent(reg):
    await reg.set_status("finance-agent", AgentStatus.quarantined)
    with pytest.raises(AgentQuarantined):
        reg.delegate(reg.issue_token("support-agent").claims, "finance-agent")


async def test_isolating_an_agent_revokes_everything_downstream(reg):
    root = reg.issue_token("support-agent")
    child = reg.delegate(root.claims, "finance-agent")
    bystander = reg.issue_token("finance-agent")  # finance's own, unrelated session

    revoked = await reg.revoke_agent("support-agent")

    assert set(revoked) == {root.claims.jti, child.claims.jti}
    for t in (root, child):
        with pytest.raises(TokenRevoked):
            reg.verify(t.token)
    reg.verify(bystander.token)


# ---------------------------------------------------------------- persistence & tampering


async def test_state_survives_a_restart(reg):
    issued = reg.issue_token("hr-agent")
    await reg.revoke(issued.claims.jti, issued.claims.expires_at)
    await reg.amend("procurement", B1_CHANGE, "Track shipments", "lead@corp.example")

    again = await fresh(reg.store)

    assert [a.agent_id for a in again.agents()] == [a.agent_id for a in reg.agents()]
    assert again.contract("procurement").version == 2
    assert len(again.amendments("procurement")) == 1
    with pytest.raises(TokenRevoked):
        again.verify(issued.token)


async def test_tampered_contract_versions_are_ignored(reg):
    await reg.amend("procurement", B1_CHANGE, "Track shipments", "lead@corp.example")
    for doc in reg.store.versions:
        if doc["role"] == "procurement":
            doc["contract"]["allowed_tools"].append("hr_db.query")  # attacker edits the DB

    again = await fresh(reg.store)
    contract = again.contract("procurement")
    assert "hr_db.query" not in contract.allowed_tools
    assert contract.version == 1  # v1 re-seeded from YAML, tampered v2 dropped
