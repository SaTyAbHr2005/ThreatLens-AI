import pytest
import yaml
from pydantic import ValidationError

from threatlens.core.schemas import (
    Action,
    ActionEvent,
    EnforcementMode,
    RoleContract,
    Sensitivity,
    SignalId,
    SignalScore,
)

PROCUREMENT_YAML = """
role: procurement
version: 3
purpose: Compare supplier prices and create purchase requests.
owner: procurement-team@corp.example
allowed_tools: [supplier_db.query, files.read, erp.create_pr, email.send]
resource_scopes:
  files.read: ["/procurement/**"]
  email.send: { recipients: ["*@corp.example"] }
data_sensitivity_ceiling: internal
egress_allowlist: [api.supplier-portal.example]
prototype_actions: ["query supplier prices for laptops"]
delegation: { may_call: [finance-agent], max_depth: 2 }
enforcement_mode: shadow
"""


def test_role_contract_from_yaml():
    c = RoleContract.model_validate(yaml.safe_load(PROCUREMENT_YAML))
    assert c.data_sensitivity_ceiling is Sensitivity.internal
    assert c.enforcement_mode is EnforcementMode.shadow
    assert c.delegation.may_call == ["finance-agent"]
    assert c.rate_envelope.actions_per_min == 30  # default


def test_sensitivity_rank_is_ordered():
    ranks = [s.rank for s in (Sensitivity.public, Sensitivity.internal, Sensitivity.confidential, Sensitivity.restricted)]
    assert ranks == [0, 1, 2, 3]


def test_signal_score_bounds():
    SignalScore(signal=SignalId.S1, value=1.0)
    with pytest.raises(ValidationError):
        SignalScore(signal=SignalId.S1, value=1.2)


def test_action_event_json_roundtrip():
    e = ActionEvent(
        agent_id="procurement-agent",
        role="procurement",
        role_version=3,
        session_id="ses_1",
        token_jti="tok_1",
        action=Action(tool="files.read", resource="/hr/salaries.xlsx", sensitivity=Sensitivity.restricted),
        scores={SignalId.S1: 0.92, SignalId.S4: 0.95},
        risk=93,
    )
    again = ActionEvent.model_validate_json(e.model_dump_json())
    assert again == e
    assert again.id.startswith("evt_")


def test_risk_out_of_range_rejected():
    with pytest.raises(ValidationError):
        ActionEvent(
            agent_id="a", role="r", role_version=1, session_id="s", token_jti="t",
            action=Action(tool="x"), risk=101,
        )
