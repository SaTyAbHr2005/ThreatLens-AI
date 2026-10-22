"""Risk fusion: nine signals → one 0–100 risk, with exact per-factor contributions.

    logit = bias + Σ wᵢ·sᵢ + w_x·(S1·S4)      S1·S4 = "off-role AND right after hidden instructions"
    risk  = 100·sigmoid(logit), then raised to any tripwire floor

A linear model is chosen on purpose: each factor's share of the risk is exactly
wᵢ·sᵢ, so explanations need no approximation (no SHAP). Weights start hand-tuned
and can be refit on labeled traffic with `fit_logistic` (M9).
"""

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from threatlens.core.schemas import SignalId, SignalScore, Tier

SIGNALS = list(SignalId)
INTERACTION = "S1xS4"

# Hand-tuned defaults. Rationale: one signal alone rarely means compromise (the bias keeps
# it low); corroborating signals compound; a canary is near-certain on its own.
DEFAULT_WEIGHTS = {
    "S0": 3.0, "S1": 3.0, "S2": 1.5, "S3": 1.5, "S4": 3.0,
    "S5": 2.5, "S6": 2.5, "S7": 2.0, "S8": 6.0, INTERACTION: 3.0,
}
DEFAULT_BIAS = -4.0

# Floors for evidence strong enough to act on alone.
FLOOR_CANARY = 90.0  # S8: bait no role ever needs
FLOOR_SENSITIVE_THEN_EGRESS = 85.0  # S5 tripwire
FLOOR_TOKEN_IN_TWO_PLACES = 75.0  # S0 = 1.0

TIER_THRESHOLDS = [(90, Tier.isolate), (75, Tier.step_up), (60, Tier.restrict), (40, Tier.monitor)]


def tier_for_risk(risk: float) -> Tier:
    return next((t for limit, t in TIER_THRESHOLDS if risk >= limit), Tier.allow)


@dataclass
class Weights:
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    bias: float = DEFAULT_BIAS
    source: str = "hand-tuned"

    @classmethod
    def load(cls, path: Path | None) -> "Weights":
        if path and path.exists():
            d = json.loads(path.read_text(encoding="utf-8"))
            return cls(weights={**DEFAULT_WEIGHTS, **d["weights"]}, bias=d["bias"], source=d.get("source", str(path)))
        return cls()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"weights": self.weights, "bias": self.bias, "source": self.source}, indent=2))


@dataclass(frozen=True)
class Fused:
    risk: float
    model_risk: float  # before floors
    contributions: dict[str, float]  # logit contribution per factor (incl. the interaction)
    floor: str | None  # which tripwire set the floor, if any

    @property
    def tier(self) -> Tier:
        return tier_for_risk(self.risk)


def _features(values: dict[str, float]) -> dict[str, float]:
    f = {s.value: values.get(s.value, 0.0) for s in SIGNALS}
    f[INTERACTION] = f["S1"] * f["S4"]
    return f


def _sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-z))


def fuse(signals: list[SignalScore], w: Weights) -> Fused:
    values = {s.signal.value: s.value for s in signals}
    f = _features(values)
    contributions = {k: w.weights.get(k, 0.0) * v for k, v in f.items() if v}
    model_risk = 100 * _sigmoid(w.bias + sum(contributions.values()))

    floors = []
    by_id = {s.signal.value: s for s in signals}
    if values.get("S8", 0) >= 1.0:
        floors.append((FLOOR_CANARY, "canary"))
    if by_id.get("S5") and by_id["S5"].details.get("tripwire"):
        floors.append((FLOOR_SENSITIVE_THEN_EGRESS, "sensitive_then_egress"))
    if values.get("S0", 0) >= 1.0:
        floors.append((FLOOR_TOKEN_IN_TWO_PLACES, "token_in_two_places"))
    floor_value, floor_name = max(floors, default=(0.0, None))
    risk = max(model_risk, floor_value)
    return Fused(round(risk, 2), round(model_risk, 2), contributions,
                 floor_name if floor_value > model_risk else None)


def without(signals: list[SignalScore], *drop: str) -> list[SignalScore]:
    """The same action with some signals removed (for counterfactuals)."""
    return [s for s in signals if s.signal.value not in drop]


def fit_logistic(rows: list[dict[str, float]], labels: list[int], *, l2: float = 0.01, epochs: int = 2000,
                 lr: float = 0.5, source: str = "fitted") -> Weights:
    """Fit weights on labeled signal vectors (1 = attack). Weights are kept ≥ 0 so every
    signal can only raise risk, which keeps explanations meaningful."""
    keys = list(DEFAULT_WEIGHTS)
    x = np.array([[_features(r)[k] for k in keys] for r in rows], dtype=float)
    y = np.array(labels, dtype=float)
    wv, b = np.array([DEFAULT_WEIGHTS[k] for k in keys]), DEFAULT_BIAS
    n = len(y)
    for _ in range(epochs):
        p = 1 / (1 + np.exp(-(x @ wv + b)))
        grad_w = x.T @ (p - y) / n + l2 * wv
        grad_b = float(np.mean(p - y))
        wv = np.maximum(0.0, wv - lr * grad_w)  # projected gradient: non-negative weights
        b -= lr * grad_b
    return Weights(weights={k: round(float(v), 4) for k, v in zip(keys, wv)}, bias=round(b, 4), source=source)
