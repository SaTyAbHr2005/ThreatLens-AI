"""Login anomaly: an Isolation Forest over a few login features (the v1 auth layer).

Features are relative to the analyst, so one model serves everyone:
    hour_shift    hours between this login and the analyst's usual login hour (0 with < 5 logins)
    new_device    1 if this device has never logged in to this account (0 on the very first login)
    failures      failed attempts on this account in the last hour
    solve_log_ms  log10 of the CAPTCHA solve time
    speed_cv      how uneven the CAPTCHA drag was

The forest is fitted at startup on a synthetic population of normal human logins
(fixed seed), and the threshold is that population's 99.5th percentile. A login above
it is blocked, with the features that made it unusual as the reason.

ponytail: a ~40-line numpy forest instead of scikit-learn (no room in 512 MB). Fit on
real login history once there is enough of it.
"""

import math
from dataclasses import dataclass

import numpy as np

FEATURES = ("hour_shift", "new_device", "failures", "solve_log_ms", "speed_cv")
REASONS = {
    "hour_shift": "unusual time of day for this account",
    "new_device": "a device this account has never used",
    "failures": "recent failed attempts",
    "solve_log_ms": "CAPTCHA solved unusually fast or slow",
    "speed_cv": "CAPTCHA movement unusually uniform or erratic",
}


def _c(n: int) -> float:
    """Average path length of an unsuccessful search in a binary tree of n points."""
    return 2 * (math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n if n > 2 else (1.0 if n == 2 else 0.0)


class IsolationForest:
    def __init__(self, n_trees: int = 100, sample: int = 256, seed: int = 0):
        self.n_trees, self.sample = n_trees, sample
        self.rng = np.random.default_rng(seed)
        self.trees: list = []

    def fit(self, x: np.ndarray) -> "IsolationForest":
        n = min(self.sample, len(x))
        limit = math.ceil(math.log2(n))
        self.trees = [self._grow(x[self.rng.choice(len(x), n, replace=False)], 0, limit) for _ in range(self.n_trees)]
        self._cn = _c(n)
        return self

    def _grow(self, x: np.ndarray, depth: int, limit: int):
        if depth >= limit or len(x) <= 1:
            return len(x)  # leaf: its size
        f = int(self.rng.integers(x.shape[1]))
        lo, hi = x[:, f].min(), x[:, f].max()
        if lo == hi:
            return len(x)
        split = self.rng.uniform(lo, hi)
        left = x[:, f] < split
        return (f, split, self._grow(x[left], depth + 1, limit), self._grow(x[~left], depth + 1, limit))

    def _path(self, row: np.ndarray, node, depth: int = 0) -> float:
        while not isinstance(node, int):
            f, split, left, right = node
            node = left if row[f] < split else right
            depth += 1
        return depth + _c(node)

    def score(self, row: np.ndarray) -> float:
        """0..1; around 0.5 is ordinary, close to 1 is isolated quickly (anomalous)."""
        mean = sum(self._path(row, t) for t in self.trees) / len(self.trees)
        return float(2 ** (-mean / self._cn))


def normal_logins(n: int = 2000, seed: int = 0) -> np.ndarray:
    """Synthetic normal human logins, in FEATURES order."""
    r = np.random.default_rng(seed)
    hour = np.where(r.random(n) < 0.05, r.uniform(0, 12, n), np.clip(np.abs(r.normal(0, 1.5, n)), 0, 12))
    return np.column_stack([
        hour,
        (r.random(n) < 0.15).astype(float),
        np.minimum(r.poisson(0.2, n), 4).astype(float),
        r.normal(math.log10(1800), 0.2, n),  # ~1.8 s typical solve
        np.clip(r.normal(0.7, 0.2, n), 0.15, 2.5),
    ])


@dataclass
class LoginRisk:
    score: float
    threshold: float
    anomalous: bool
    reasons: list[str]
    features: dict[str, float]


class LoginAnomalyModel:
    def __init__(self, seed: int = 0):
        train = normal_logins(seed=seed)
        self.forest = IsolationForest(seed=seed).fit(train)
        scores = np.array([self.forest.score(row) for row in train[:500]])  # enough for the quantile, fast startup
        self.threshold = float(np.quantile(scores, 0.995))
        self.lo, self.hi = np.quantile(train, 0.01, axis=0), np.quantile(train, 0.99, axis=0)

    def assess(self, features: dict[str, float]) -> LoginRisk:
        row = np.array([features[f] for f in FEATURES], dtype=float)
        s = self.forest.score(row)
        # Explain with the features outside the normal population's 1–99% range.
        reasons = [REASONS[f] for i, f in enumerate(FEATURES) if row[i] > self.hi[i] or row[i] < self.lo[i]]
        anomalous = s > self.threshold
        if anomalous and features["new_device"] and REASONS["new_device"] not in reasons:
            reasons.append(REASONS["new_device"])  # common alone, but it counts when combined with others
        if anomalous and not reasons:
            reasons = ["an unusual combination of login features"]
        return LoginRisk(round(s, 3), round(self.threshold, 3), anomalous, reasons, features)
