"""Runs the evaluation dataset through an isolated copy of the real stack.

Every session goes through the real gateway, detector, fusion and response engine
(in memory, so evaluation never touches production baselines or alerts). Each action's
nine signal scores are recorded, so the same traffic can be re-fused under ablated
configurations without re-running it. Fleet immunity is left out on purpose: each
attack variant is judged on its own, not on a signature learned from an earlier one.

Two passes: `shadow=True` scores every action without containing anyone, so every
signal is observed for the ablation; `shadow=False` enforces, for the outcome metrics
(work preserved, data stopped, attribution, latency).
"""

import base64
import time
from dataclasses import dataclass, field

from threatlens.core.bus import EventBus, Topics
from threatlens.core.config import Settings
from threatlens.core.schemas import EnforcementMode, RuntimeFingerprint, SignalScore
from threatlens.core.security import InvalidToken
from threatlens.detection import CachedEmbedder, Detector, HashingEmbedder
from threatlens.fusion import FusionScorer, MemoryAlertStore, Weights
from threatlens.gateway import Catalog, Gateway
from threatlens.identity import MemoryRegistryStore, Registry
from threatlens.intel import ImmuneScanner, SignatureBook
from threatlens.response import MemoryDecisionStore, ResponseOrchestrator
from threatlens.scanner import ContentForensics
from threatlens.sim import EnterpriseConnector, ExternalSink
from threatlens.sim.encode import encode
from threatlens.sim.runner import GRANTS

from .dataset import Session, _benign_steps

ALLOWED = ("allow", "allow_logged")
BENIGN_AGENTS_PER_ROLE = 3  # benign sessions share a small fleet, as real agents do


@dataclass
class ActionTrace:
    tool: str
    malicious: bool
    warmup: bool
    signals: list[SignalScore]
    risk: float | None  # live risk under the full system
    decision: str
    score_ms: float  # detection + fusion + response for this action
    call_ms: float  # the whole gateway call, tool included


@dataclass
class SessionTrace:
    id: str
    scenario: str
    label: str
    agent_id: str
    novel: bool = False  # a held-out attack variant
    actions: list[ActionTrace] = field(default_factory=list)
    cause_id: str | None = None  # ground truth: the poisoned content's id
    alert_cause_id: str | None = None  # what the alert named
    exfil_bytes: int = 0
    final_status: str = "active"


class _Recorder:
    """Wraps the real scorer to keep each action's signals and timing."""

    def __init__(self, inner):
        self.inner = inner
        self.last = None
        self.last_ms = 0.0

    async def score(self, event, ctx):
        t = time.perf_counter()
        res = await self.inner.score(event, ctx)
        self.last_ms = (time.perf_counter() - t) * 1000
        self.last = res
        return res


class Harness:
    def __init__(self, settings: Settings, embedder: CachedEmbedder | None = None, weights: Weights | None = None,
                 *, shadow: bool = False):
        self.settings = settings
        self.shadow = shadow
        self.registry = Registry(MemoryRegistryStore(), settings)
        self.catalog = Catalog.load(settings.catalog_dir)
        self.bus = EventBus()
        self.detector = Detector(self.registry, self.catalog, embedder or CachedEmbedder(HashingEmbedder()))
        self.fusion = FusionScorer(self.detector, self.registry, MemoryAlertStore(), weights=weights or Weights())
        self.response = ResponseOrchestrator(self.fusion, self.registry, MemoryDecisionStore())
        self.sink = ExternalSink()
        self.recorder = _Recorder(self.response)
        self.gateway = Gateway(self.registry, self.catalog, EnterpriseConnector(self.catalog, self.sink, settings),
                               scorer=self.recorder, scanner=ImmuneScanner(ContentForensics(), SignatureBook()),
                               settings=settings, bus=self.bus)
        self.gateway.approvals, self.response.gateway = self.response.approvals, self.gateway
        self.bus.subscribe(Topics.action_scored, self.detector.observe)
        self.fusion.attach(self.bus)
        self.response.attach(self.bus)
        self._tokens: dict[str, str] = {}  # one token per agent, as a deployed agent holds

    async def start(self) -> None:
        await self.registry.load()
        if self.shadow:  # this registry is private to the run, so its contracts can be switched in place
            for contract in self.registry.roles():
                contract.enforcement_mode = EnforcementMode.shadow

    async def _agent(self, agent_id: str, role: str) -> str:
        if agent_id not in self._tokens:
            await self.registry.create_agent(agent_id, role, f"{role}-team@corp.example", GRANTS.get(role))
            self._tokens[agent_id] = self.registry.issue_token(agent_id).token
        return agent_id

    async def run(self, sessions: list[Session]) -> list[SessionTrace]:
        import random

        rng = random.Random(0)
        traces = []
        for i, s in enumerate(sessions):
            if s.label == "benign":
                agent = await self._agent(f"{s.role}-eval-{i % BENIGN_AGENTS_PER_ROLE}", s.role)
            else:
                agent = await self._agent(f"{s.role}-eval-{s.id}", s.role)  # a fresh, never-seen agent
            traces.append(await self._session(s, agent, rng))
        await self.bus.drain()
        return traces

    async def _session(self, s: Session, agent: str, rng) -> SessionTrace:
        tr = SessionTrace(id=s.id, scenario=s.scenario, label=s.label, agent_id=agent, novel=s.novel)
        session_id = f"eval-{s.id}"
        sink_start = self.sink.total_bytes
        for step in _benign_steps(s.role, rng, s.warmup, rare=False):  # a clean, typical history
            await self._act(tr, session_id, step, warmup=True)
        for step in s.steps:
            if step.kind == "read":
                cid = await self._read(agent, session_id, step)
                if step.is_cause:
                    tr.cause_id = cid
            else:
                await self._act(tr, session_id, step, warmup=False)
        await self.bus.drain()
        alert = self.fusion.open_alert(agent, session_id)
        tr.alert_cause_id = alert.cause_content_id if alert else None
        tr.exfil_bytes = self.sink.total_bytes - sink_start
        tr.final_status = self.registry.agent(agent).status.value
        return tr

    async def _read(self, agent: str, session_id: str, step) -> str | None:
        doc = encode(step.secret, step.technique or "visible", cover=step.text or "Document.")
        raw = base64.b64decode(doc["pdf_b64"]) if doc["pdf_b64"] else None
        try:
            item = await self.gateway.register_content(self._tokens[agent], session_id, step.source,
                                                       doc["carrier"], doc["text"] or "", raw)
        except InvalidToken:
            return None
        return item.id

    async def _act(self, tr: SessionTrace, session_id: str, step, *, warmup: bool) -> None:
        self.recorder.last, self.recorder.last_ms = None, 0.0
        t = time.perf_counter()
        try:
            res = await self.gateway.tool_call(self._tokens[tr.agent_id], session_id, step.tool, dict(step.args),
                                               RuntimeFingerprint(host="worker-1", sdk="eval"))
            decision, risk = res.decision.value, res.risk
        except InvalidToken:  # isolated earlier in the session: nothing runs
            decision, risk = "quarantine", None
        call_ms = (time.perf_counter() - t) * 1000
        await self.bus.drain()  # let the detector learn before the next action, as in production
        sr = self.recorder.last
        tr.actions.append(ActionTrace(tool=step.tool, malicious=step.malicious, warmup=warmup,
                                      signals=list(sr.signals) if sr else [], risk=risk, decision=decision,
                                      score_ms=self.recorder.last_ms, call_ms=call_ms))
