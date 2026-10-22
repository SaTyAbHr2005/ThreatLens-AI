"""What 'normal' looks like, per agent and per role (cohort).

Learning is anchored: only clean actions (allowed, every signal < 0.5) are learned,
so an attacker can't slowly teach the detector that their behavior is normal.
The S7 anchor is frozen after ANCHOR_SIZE clean actions and only resets when the
Role Contract changes through a signed amendment.

ponytail: one in-process store, snapshotted to Atlas. With several replicas this
becomes Redis keyed the same way (PRODUCTION.md §3).
"""

import math
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

ANCHOR_SIZE = 30
RECENT_SIZE = 50
SESSION_BUCKETS = (5, 10, 20, 40)
SESSION_FEATURES = ("distinct_tools", "distinct_classes", "max_sensitivity", "external_egress", "denied", "kb_out")


@dataclass
class Markov:
    trans: dict[str, Counter] = field(default_factory=dict)

    def add(self, prev: str, cur: str) -> None:
        self.trans.setdefault(prev, Counter())[cur] += 1

    def ratio(self, prev: str, cur: str, vocab: int, alpha: float = 0.5) -> tuple[float, int, int]:
        """P(cur|prev) / P(most likely next|prev), with Laplace smoothing. Returns (ratio, n_prev, count)."""
        row = self.trans.get(prev, Counter())
        n = sum(row.values())
        count = row.get(cur, 0)
        top = max(row.values(), default=0)
        return (count + alpha) / (top + alpha), n, count

    def tokens(self) -> set[str]:
        return set(self.trans) | {t for row in self.trans.values() for t in row}


@dataclass
class Welford:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0


@dataclass
class AgentBaseline:
    role_version: int = 0
    markov: Markov = field(default_factory=Markov)
    hosts: Counter = field(default_factory=Counter)
    sdks: Counter = field(default_factory=Counter)
    destinations: set[str] = field(default_factory=set)
    n_clean: int = 0
    # S7 anchor
    anchor_s1: list[float] = field(default_factory=list)
    anchor_classes: Counter = field(default_factory=Counter)
    cusum: float = 0.0
    recent_classes: deque = field(default_factory=lambda: deque(maxlen=RECENT_SIZE))
    # transient (not persisted): token → (host, monotonic time)
    jti_hosts: dict[str, tuple[str, float]] = field(default_factory=dict)

    @property
    def anchor_frozen(self) -> bool:
        return len(self.anchor_s1) >= ANCHOR_SIZE

    @property
    def anchor_mean(self) -> float:
        return sum(self.anchor_s1) / len(self.anchor_s1) if self.anchor_s1 else 0.0

    def reanchor(self, role_version: int) -> None:
        """A signed amendment changed the role: start a fresh anchor for the new contract."""
        self.role_version = role_version
        self.anchor_s1, self.anchor_classes, self.cusum = [], Counter(), 0.0


@dataclass
class RoleBaseline:
    markov: Markov = field(default_factory=Markov)
    destinations: set[str] = field(default_factory=set)
    sessions: dict[str, Welford] = field(default_factory=dict)  # "feature@bucket" -> stats

    def stat(self, feature: str, bucket: int) -> Welford:
        return self.sessions.setdefault(f"{feature}@{bucket}", Welford())


class BaselineStore:
    def __init__(self) -> None:
        self.agents: dict[str, AgentBaseline] = {}
        self.roles: dict[str, RoleBaseline] = {}
        self.dirty = False

    def agent(self, agent_id: str, role_version: int) -> AgentBaseline:
        b = self.agents.get(agent_id)
        if b is None:
            b = self.agents[agent_id] = AgentBaseline(role_version=role_version)
        elif b.role_version != role_version:
            b.reanchor(role_version)
        return b

    def role(self, role: str) -> RoleBaseline:
        return self.roles.setdefault(role, RoleBaseline())

    def vocab(self, agent: AgentBaseline, role: RoleBaseline) -> int:
        return max(10, len(agent.markov.tokens() | role.markov.tokens()))

    # ------------------------------------------------------------ persistence

    def snapshot(self) -> dict[str, Any]:
        return {
            "agents": {
                a: {
                    "role_version": b.role_version,
                    "markov": {k: dict(v) for k, v in b.markov.trans.items()},
                    "hosts": dict(b.hosts),
                    "sdks": dict(b.sdks),
                    "destinations": sorted(b.destinations),
                    "n_clean": b.n_clean,
                    "anchor_s1": b.anchor_s1,
                    "anchor_classes": dict(b.anchor_classes),
                    "cusum": b.cusum,
                    "recent_classes": list(b.recent_classes),
                }
                for a, b in self.agents.items()
            },
            "roles": {
                r: {
                    "markov": {k: dict(v) for k, v in b.markov.trans.items()},
                    "destinations": sorted(b.destinations),
                    "sessions": {k: [w.n, w.mean, w.m2] for k, w in b.sessions.items()},
                }
                for r, b in self.roles.items()
            },
        }

    @classmethod
    def restore(cls, data: dict[str, Any]) -> "BaselineStore":
        s = cls()
        for a, d in data.get("agents", {}).items():
            s.agents[a] = AgentBaseline(
                role_version=d["role_version"],
                markov=Markov({k: Counter(v) for k, v in d["markov"].items()}),
                hosts=Counter(d["hosts"]),
                sdks=Counter(d["sdks"]),
                destinations=set(d["destinations"]),
                n_clean=d["n_clean"],
                anchor_s1=list(d["anchor_s1"]),
                anchor_classes=Counter(d["anchor_classes"]),
                cusum=d["cusum"],
                recent_classes=deque(d["recent_classes"], maxlen=RECENT_SIZE),
            )
        for r, d in data.get("roles", {}).items():
            s.roles[r] = RoleBaseline(
                markov=Markov({k: Counter(v) for k, v in d["markov"].items()}),
                destinations=set(d["destinations"]),
                sessions={k: Welford(*v) for k, v in d["sessions"].items()},
            )
        return s


def jensen_shannon(p: Counter, q: Counter) -> float:
    """0 (same distribution) … 1 (disjoint), base-2."""
    keys = set(p) | set(q)
    sp, sq = sum(p.values()), sum(q.values())
    if not keys or not sp or not sq:
        return 0.0

    def kl(a: dict[str, float], m: dict[str, float]) -> float:
        return sum(a[k] * math.log2(a[k] / m[k]) for k in keys if a[k] > 0)

    pp = {k: p.get(k, 0) / sp for k in keys}
    qq = {k: q.get(k, 0) / sq for k in keys}
    mm = {k: (pp[k] + qq[k]) / 2 for k in keys}
    return max(0.0, min(1.0, 0.5 * kl(pp, mm) + 0.5 * kl(qq, mm)))
