import pytest

from threatlens.core.config import get_settings
from threatlens.core.schemas import Sensitivity
from threatlens.identity import InvalidAmendment, apply_changes, load_role_dir
from threatlens.identity.contracts import sign, verify_signature


@pytest.fixture(scope="module")
def contracts():
    return {c.role: c for c in load_role_dir(get_settings().roles_dir)}


def test_all_role_files_are_valid(contracts):
    assert set(contracts) == {"procurement", "hr", "finance", "support"}
    for c in contracts.values():
        assert c.allowed_tools and c.prototype_actions, c.role


def test_delegation_graph_matches_scenarios(contracts):
    # A4 (support → finance chain hijack) and procurement → finance must be possible.
    assert contracts["support"].delegation.may_call == ["finance-agent"]
    assert contracts["procurement"].delegation.may_call == ["finance-agent"]
    assert contracts["hr"].delegation.may_call == []


def test_procurement_cannot_reach_hr_data(contracts):
    p = contracts["procurement"]
    assert not any(s.startswith("/hr") for s in p.resource_scopes["files.read"])
    assert p.data_sensitivity_ceiling is Sensitivity.internal


def test_list_add_remove_and_version_bump(contracts):
    p = contracts["procurement"]
    new = apply_changes(p, {"allowed_tools": {"add": ["logistics_api.track"], "remove": ["web.fetch"]}})
    assert new.version == p.version + 1
    assert "logistics_api.track" in new.allowed_tools
    assert "web.fetch" not in new.allowed_tools
    assert p.allowed_tools != new.allowed_tools  # original untouched


def test_resource_scope_merge_and_removal(contracts):
    p = contracts["procurement"]
    new = apply_changes(p, {"resource_scopes": {"logistics_api.track": ["shipments.*"], "web.fetch": None}})
    assert new.resource_scopes["logistics_api.track"] == ["shipments.*"]
    assert "web.fetch" not in new.resource_scopes
    assert new.resource_scopes["files.read"] == p.resource_scopes["files.read"]


@pytest.mark.parametrize(
    "changes",
    [{}, {"role": "x"}, {"version": 9}, {"not_a_field": 1}, {"allowed_tools": {"append": ["x"]}},
     {"data_sensitivity_ceiling": "top-secret"}],
)
def test_invalid_changes_rejected(contracts, changes):
    with pytest.raises(InvalidAmendment):
        apply_changes(contracts["procurement"], changes)


def test_signatures_detect_tampering():
    body = {"role": "procurement", "allowed_tools": ["files.read"]}
    sig = sign(body, "k")
    assert verify_signature(body, sig, "k")
    assert not verify_signature({**body, "allowed_tools": ["files.read", "hr_db.query"]}, sig, "k")
    assert not verify_signature(body, sig, "other-key")
    assert not verify_signature(body, None, "k")
