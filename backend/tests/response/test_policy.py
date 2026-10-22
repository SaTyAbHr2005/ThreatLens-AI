from threatlens.core.schemas import AgentStatus as S
from threatlens.response import escalation, is_strike, relaxation


def test_escalation_contains_first_and_isolates_only_on_certainty_or_persistence():
    assert escalation(S.active, 10, 5, (), 0) is S.active
    assert escalation(S.active, 65, 30, (), 0) is S.restricted
    assert escalation(S.active, 99, 99, (), 0) is S.step_up  # high risk alone: contain, don't kill
    assert escalation(S.active, 20, 68, (), 0) is S.restricted  # slow drift raises drift, not risk
    assert escalation(S.active, 99, 99, ("canary",), 0) is S.quarantined
    assert escalation(S.active, 75, 75, ("token_in_two_places", "sensitive_then_egress"), 0) is S.quarantined
    assert escalation(S.step_up, 99, 99, (), 3) is S.quarantined  # kept attacking while contained
    assert escalation(S.step_up, 10, 10, (), 0) is S.step_up  # never lowered here
    assert escalation(S.quarantined, 0, 0, (), 0) is S.quarantined


def test_strikes_only_count_while_contained():
    assert not is_strike(S.active, 99)
    assert is_strike(S.step_up, 80) and is_strike(S.restricted, 75)
    assert not is_strike(S.step_up, 50)


def test_relaxation_is_gradual_and_never_leaves_isolation():
    assert relaxation(S.step_up, 50, 9) is S.step_up  # not enough clean actions yet
    assert relaxation(S.step_up, 50, 10) is S.restricted
    assert relaxation(S.step_up, 70, 30) is S.step_up  # drift still too high
    assert relaxation(S.restricted, 30, 10) is S.active
    assert relaxation(S.quarantined, 0, 1000) is S.quarantined
