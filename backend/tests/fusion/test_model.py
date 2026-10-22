import random

from threatlens.core.schemas import SignalId, SignalScore, Tier
from threatlens.fusion import DriftTracker, Weights, fit_logistic, fuse, tier_for_risk


def sig(**values) -> list[SignalScore]:
    details = values.pop("details", {})
    return [SignalScore(signal=SignalId(k), value=v, evidence=f"{k} evidence", details=details.get(k, {}))
            for k, v in values.items()]


W = Weights()


def test_quiet_action_scores_low_and_a1_scores_high():
    assert fuse(sig(S1=0.1, S2=0.1), W).risk < 5
    a1 = fuse(sig(S1=0.9, S4=0.81, S5=1.0), W)
    assert a1.risk >= 95 and a1.tier is Tier.isolate


def test_single_weak_signals_stay_below_alerting():
    for s in (sig(S2=0.7), sig(S1=1.0), sig(S7=0.8, S1=0.3), sig(S0=0.6)):
        assert fuse(s, W).risk < 60, s


def test_tripwire_floors():
    assert fuse(sig(S8=1.0), W).risk == 90 and fuse(sig(S8=1.0), W).floor == "canary"
    assert fuse(sig(S0=1.0), W).risk == 75
    tripped = fuse(sig(S5=0.6, details={"S5": {"tripwire": "sensitive_then_egress"}}), W)
    assert tripped.risk == 85 and tripped.floor == "sensitive_then_egress"
    # A floor never lowers a risk the model already put higher.
    assert fuse(sig(S8=1.0, S1=1.0, S4=0.9, S5=1.0), W).floor is None


def test_contributions_are_exact_and_include_the_interaction():
    f = fuse(sig(S1=0.9, S4=0.8), W)
    assert f.contributions["S1"] == W.weights["S1"] * 0.9
    assert f.contributions["S1xS4"] == W.weights["S1xS4"] * 0.9 * 0.8


def test_tier_thresholds():
    assert [tier_for_risk(r) for r in (10, 45, 65, 80, 95)] == [
        Tier.allow, Tier.monitor, Tier.restrict, Tier.step_up, Tier.isolate]


def test_fit_logistic_learns_and_keeps_weights_non_negative(tmp_path):
    rng = random.Random(7)
    rows, labels = [], []
    for _ in range(300):  # benign: low, noisy signals
        rows.append({k: rng.random() * 0.3 for k in ("S1", "S2", "S5")})
        labels.append(0)
    for _ in range(300):  # attacks: off-role right after tainted content
        rows.append({"S1": 0.7 + rng.random() * 0.3, "S4": 0.6 + rng.random() * 0.4, "S2": rng.random() * 0.3})
        labels.append(1)
    w = fit_logistic(rows, labels, source="test")
    assert all(v >= 0 for v in w.weights.values())
    benign = sum(fuse(sig(**r), w).risk < 50 for r, y in zip(rows, labels) if y == 0)
    attack = sum(fuse(sig(**r), w).risk >= 50 for r, y in zip(rows, labels) if y == 1)
    assert benign >= 290 and attack >= 290

    path = tmp_path / "w.json"
    w.save(path)
    again = Weights.load(path)
    assert again.weights == {**W.weights, **w.weights} and again.source == "test"
    assert Weights.load(tmp_path / "missing.json").source == "hand-tuned"


def test_drift_spikes_fast_fades_slowly_and_tracks_slow_drift():
    d = DriftTracker()
    assert d.update("a", 2) < 5
    assert d.update("a", 95) >= 95  # one alarming action shows immediately
    for _ in range(20):
        value = d.update("a", 2)
    assert 20 < value < 50  # still visible after 20 clean actions, but fading
    assert DriftTracker().update("b", 10, s7=0.8) == 68.0  # slow drift alone can raise drift
    d.reset("a")
    assert d.get("a") == 0.0
