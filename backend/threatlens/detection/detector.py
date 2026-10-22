"""M4 Behavioral Detection: scores every action on nine signals (the gateway's ActionScorer).

Fusion into one risk score and tier is M5's job; this module only measures.
"""

import asyncio
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass

from threatlens.core.schemas import ActionEvent, DecisionType, SignalScore
from threatlens.gateway.catalog import Catalog
from threatlens.gateway.hooks import ScoreResult, ScoringContext
from threatlens.identity import Registry

from .baselines import ANCHOR_SIZE, SESSION_BUCKETS, SESSION_FEATURES, BaselineStore
from .describe import describe
from .embedder import CachedEmbedder
from .roles import RoleIndex
from .signals import (
    Inputs,
    s0_runtime,
    s1_role,
    s2_sequence,
    s3_session,
    s4_provenance,
    s5_sensitivity_egress,
    s6_delegation,
    s7_drift,
    s8_canary,
    session_features,
    token_for,
)

log = logging.getLogger(__name__)

CLEAN_MAX_SIGNAL = 0.5
START = "^start"


@dataclass
class _Pending:
    """What score() saw, kept until the finished event comes back on the bus to be learned."""

    agent_id: str
    role: str
    role_version: int
    prev_token: str
    token: str
    s1: float
    resource_class: str
    features: dict[str, float]
    step: int


class Detector:
    def __init__(self, registry: Registry, catalog: Catalog, embedder: CachedEmbedder,
                 store: BaselineStore | None = None):
        self.registry = registry
        self.catalog = catalog
        self.embedder = embedder
        self.store = store or BaselineStore()
        self.roles = RoleIndex(embedder, catalog)
        self._last_token: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._pending: OrderedDict[str, _Pending] = OrderedDict()

    # ------------------------------------------------------------ scoring

    async def score(self, event: ActionEvent, ctx: ScoringContext) -> ScoreResult:
        a, contract = ctx.action, ctx.contract
        text = describe(a)
        # Embedding is CPU work; keep it off the event loop.
        rv, vec = await asyncio.to_thread(self._vectors, contract, text)

        agent_b = self.store.agent(ctx.agent.agent_id, contract.version)
        role_b = self.store.role(contract.role)
        key = (ctx.agent.agent_id, event.session_id)
        x = Inputs(event=event, ctx=ctx, agent_b=agent_b, role_b=role_b, store=self.store,
                   prev_token=self._last_token.get(key, START), token=token_for(a), now=time.monotonic())
        self._remember_token(key, x.token)

        s0 = s0_runtime(x)
        s1 = s1_role(x, rv, vec, self.embedder.floor)
        s2 = s2_sequence(x)
        step = ctx.session.step + 1
        features = session_features(x)
        s3 = s3_session(x, features, step)
        s5 = s5_sensitivity_egress(x)
        s6 = s6_delegation(x, self._root_contract(ctx))
        s8 = s8_canary(x)
        # Provenance only matters if the action itself is unusual: taint × novelty.
        s4 = s4_provenance(x, novelty=max(s1.value, s5.value, s6.value, s8.value))
        s7 = s7_drift(x, s1.value)

        signals = [s0, s1, s2, s3, s4, s5, s6, s7, s8]
        self._pending[event.id] = _Pending(ctx.agent.agent_id, contract.role, contract.version, x.prev_token,
                                           x.token, s1.value, a.label.resource_class, features, step)
        while len(self._pending) > 10_000:
            self._pending.popitem(last=False)
        return ScoreResult(scores={s.signal: s.value for s in signals}, signals=signals)

    def _vectors(self, contract, text):
        rv = self.roles.get(contract)
        return rv, self.embedder.embed([text])[0]

    def _root_contract(self, ctx: ScoringContext):
        if ctx.claims.depth == 0:
            return None
        try:
            return self.registry.contract(ctx.claims.root_role)
        except Exception:
            return None

    def _remember_token(self, key: tuple[str, str], token: str) -> None:
        self._last_token[key] = token
        self._last_token.move_to_end(key)
        while len(self._last_token) > 20_000:
            self._last_token.popitem(last=False)

    # ------------------------------------------------------------ learning (bus subscriber)

    async def observe(self, event: ActionEvent) -> None:
        """Learn from a finished action, but only if it was clean (anchored baseline)."""
        p = self._pending.pop(event.id, None)
        if p is None or not self.is_clean(event):
            return
        agent_b = self.store.agent(p.agent_id, p.role_version)
        role_b = self.store.role(p.role)
        agent_b.markov.add(p.prev_token, p.token)
        role_b.markov.add(p.prev_token, p.token)
        agent_b.n_clean += 1
        if event.runtime.host:
            agent_b.hosts[event.runtime.host] += 1
        if event.runtime.sdk:
            agent_b.sdks[event.runtime.sdk] += 1
        if event.action.destination:
            agent_b.destinations.add(event.action.destination)
            role_b.destinations.add(event.action.destination)
        if len(agent_b.anchor_s1) < ANCHOR_SIZE:
            agent_b.anchor_s1.append(p.s1)
            agent_b.anchor_classes[p.resource_class] += 1
        if p.step in SESSION_BUCKETS:
            for f in SESSION_FEATURES:
                role_b.stat(f, p.step).add(p.features[f])
        self.store.dirty = True

    @staticmethod
    def is_clean(event: ActionEvent) -> bool:
        if event.decision not in (DecisionType.allow, DecisionType.allow_logged):
            return False
        if event.would_be not in (None, DecisionType.allow, DecisionType.allow_logged):
            return False  # shadow mode: enforce mode would have blocked it
        if event.label and event.label.startswith("attack"):
            return False  # labeled evaluation traffic
        return max(event.scores.values(), default=0.0) < CLEAN_MAX_SIGNAL


def evidence_for(signals: list[SignalScore], minimum: float = 0.3) -> list[SignalScore]:
    """Signals worth explaining, strongest first (used by M5)."""
    return sorted((s for s in signals if s.value >= minimum and s.evidence), key=lambda s: -s.value)
