"""M5 FusionScorer: Detector signals → risk, drift and alerts. Plugs into the gateway as its ActionScorer.

Hot path (per tool call): detect → fuse → update drift → build/update the alert in memory.
Everything slow (saving alerts, writing narratives, persisting drift) runs as bus
subscribers after the response has gone back to the agent.
"""

import logging
from collections import OrderedDict
from collections.abc import Callable

from threatlens.core.bus import EventBus, Topics
from threatlens.core.llm import LLMRouter
from threatlens.core.schemas import ActionEvent, Alert, SignalId, Tier, utcnow
from threatlens.gateway.hooks import ScoreResult, ScoringContext
from threatlens.gateway.policy import TIER_ORDER
from threatlens.identity import Registry, UnknownAgent

from .drift import DriftTracker
from .explain import ContentCache, build_alert
from .model import Weights, fuse
from .narrative import write_narrative

log = logging.getLogger(__name__)

ALERT_THRESHOLD = 60.0  # the Restrict tier
DRIFT_PERSIST_STEP = 2.0


class FusionScorer:
    def __init__(self, detector, registry: Registry, alerts, *, weights: Weights | None = None,
                 llm: LLMRouter | None = None, bus: EventBus | None = None, content: ContentCache | None = None):
        self.detector = detector
        self.registry = registry
        self.alerts = alerts
        self.weights = weights or Weights()
        self.llm = llm
        self.bus = bus
        self.content = content or ContentCache()
        self.drift = DriftTracker()
        self._open: OrderedDict[tuple[str, str], Alert] = OrderedDict()  # one open alert per agent session
        self._narrated: dict[str, Tier] = {}
        self._persisted_drift: dict[str, float] = {}

    # ------------------------------------------------------------ hot path

    async def score(self, event: ActionEvent, ctx: ScoringContext) -> ScoreResult:
        detected = await self.detector.score(event, ctx)
        fused = fuse(detected.signals, self.weights)
        ctx.agent.drift = self.drift.update(ctx.agent.agent_id, fused.risk, detected.scores.get(SignalId.S7, 0.0))

        alert_id = None
        if fused.risk >= ALERT_THRESHOLD:
            alert_id = self._raise_or_update(ctx, event, detected.signals, fused).id
        return ScoreResult(scores=detected.scores, signals=detected.signals, risk=fused.risk, alert_id=alert_id,
                           floor=fused.floor, tripwires=fused.tripwires)

    def _raise_or_update(self, ctx, event, signals, fused) -> Alert:
        key = (event.agent_id, event.session_id)
        current = self._open.get(key)
        if current is None or current.status.value != "open":
            alert = build_alert(ctx, event, signals, fused, self.weights, self.content)
            self._remember(key, alert)
            self._publish(Topics.alert_raised, alert)
            return alert
        # Same agent session: fold into the open alert. The strongest action explains it.
        current.action_count += 1
        current.timeline = (current.timeline + [event.id])[-30:]
        current.updated_at = utcnow()
        if fused.risk > current.risk:
            fresh = build_alert(ctx, event, signals, fused, self.weights, self.content)
            # Keep the original cause if this action has none of its own (the PDF still caused it).
            cause, decoded = current.cause_content_id, current.decoded_injection
            for field in ("risk", "tier", "headline", "factors", "cause_content_id", "decoded_injection",
                          "counterfactual", "frameworks", "recommendations", "scores", "floor", "event_id"):
                setattr(current, field, getattr(fresh, field))
            if not current.cause_content_id:
                current.cause_content_id, current.decoded_injection = cause, decoded
        self._publish(Topics.alert_updated, current)
        return current

    def _remember(self, key, alert: Alert) -> None:
        self._open[key] = alert
        self._open.move_to_end(key)
        while len(self._open) > 5000:
            self._open.popitem(last=False)

    def _publish(self, topic: str, alert: Alert) -> None:
        if self.bus:
            self.bus.publish(topic, alert.model_copy(deep=True))

    # ------------------------------------------------------------ off the hot path (bus subscribers)

    def attach(self, bus: EventBus) -> list[Callable[[], None]]:
        self.bus = bus
        return [
            bus.subscribe(Topics.content_scanned, self.content.add),
            bus.subscribe(Topics.alert_raised, self._on_raised),
            bus.subscribe(Topics.alert_updated, self._on_updated),
            bus.subscribe(Topics.action_scored, self._on_action),
        ]

    async def _on_raised(self, alert: Alert) -> None:
        await self.alerts.save(alert)

    async def _on_updated(self, alert: Alert) -> None:
        await self.alerts.save(alert)

    async def _on_action(self, event: ActionEvent) -> None:
        """After the action finished: persist drift, and write the alert's narrative now that
        the outcome (allowed / blocked / held) and the containment applied are known."""
        agent_id = event.agent_id
        try:
            agent = self.registry.agent(agent_id)
        except UnknownAgent:
            return
        if abs(agent.drift - self._persisted_drift.get(agent_id, 0.0)) >= DRIFT_PERSIST_STEP:
            self._persisted_drift[agent_id] = agent.drift
            await self.registry.set_status(agent_id, agent.status, agent.drift)

        alert = self.live_alert(event.alert_id) if event.alert_id else None
        if alert is None:
            return
        stage = (TIER_ORDER.index(alert.tier), alert.containment.value if alert.containment else "")
        if self._narrated.get(alert.id) != stage:  # first time, or the situation escalated
            self._narrated[alert.id] = stage
            await self._narrate(alert, agent.role, event)

    async def _narrate(self, alert: Alert, role: str, event: ActionEvent) -> None:
        text, source = await write_narrative(self.llm, alert, role, event)
        if not text:
            return
        alert.narrative, alert.narrative_source = text, source
        await self.save_alert(alert)

    # ------------------------------------------------------------ used by M6 and the API

    def open_alert(self, agent_id: str, session_id: str) -> Alert | None:
        return self._open.get((agent_id, session_id))

    def live_alert(self, alert_id: str) -> Alert | None:
        return next((a for a in self._open.values() if a.id == alert_id), None)

    async def save_alert(self, alert: Alert) -> None:
        """Persist an alert changed outside scoring (containment notes, analyst feedback)."""
        alert.updated_at = utcnow()
        for key, a in list(self._open.items()):
            if a.id == alert.id:
                self._open[key] = alert
        await self.alerts.save(alert)
        if self.bus:
            self.bus.publish(Topics.alert_updated, alert.model_copy(deep=True))

    def reset_agent(self, agent_id: str) -> None:
        """An analyst released the agent: its drift starts over and new alerts start fresh."""
        self.drift.reset(agent_id)
        for key in [k for k in self._open if k[0] == agent_id]:
            self._open.pop(key)
