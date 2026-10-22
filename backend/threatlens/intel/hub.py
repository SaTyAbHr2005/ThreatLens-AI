"""M7 Threat Intelligence Hub: a passive subscriber. If it fails, detection and enforcement go on.

Listens to the event bus to maintain the signature feed, the fleet trend, and
leaderboards (most-attacked roles, most-used hiding techniques, most-blocked destinations).
"""

import logging
from collections import Counter
from collections.abc import Callable

from threatlens.core.bus import EventBus, Topics
from threatlens.core.schemas import ActionEvent, Alert, AlertFeedback, ContentItem, DecisionType
from threatlens.fusion import ContentCache
from threatlens.identity import Registry, UnknownAgent

from .signatures import SignatureBook, SignatureStatus
from .trend import TrendBook

log = logging.getLogger(__name__)


class IntelHub:
    def __init__(self, registry: Registry, book: SignatureBook):
        self.registry = registry
        self.book = book
        self.trend = TrendBook()
        self.content = ContentCache()
        self.attacked_roles: Counter = Counter()
        self.blocked_destinations: Counter = Counter()
        self._alerts_seen: set[str] = set()
        self._feedback_seen: set[tuple[str, str]] = set()

    def attach(self, bus: EventBus) -> list[Callable[[], None]]:
        return [
            bus.subscribe(Topics.content_scanned, self._safe(self._on_content)),
            bus.subscribe(Topics.action_scored, self._safe(self._on_action)),
            bus.subscribe(Topics.alert_raised, self._safe(self._on_alert)),
            bus.subscribe(Topics.alert_updated, self._safe(self._on_alert)),
        ]

    @staticmethod
    def _safe(handler):
        async def wrapped(payload):
            try:
                await handler(payload)
            except Exception:
                log.exception("intel handler failed; detection is unaffected")
        return wrapped

    async def _on_content(self, item: ContentItem) -> None:
        await self.content.add(item)
        await self.book.observe(item)

    async def _on_action(self, e: ActionEvent) -> None:
        try:
            drift = self.registry.agent(e.agent_id).drift
        except UnknownAgent:
            return
        self.trend.add(e, drift)
        if e.decision in (DecisionType.deny, DecisionType.quarantine) and e.action.destination:
            self.blocked_destinations[e.action.destination] += 1

    async def _on_alert(self, alert: Alert) -> None:
        if alert.id not in self._alerts_seen:
            self._alerts_seen.add(alert.id)
            try:
                self.attacked_roles[self.registry.agent(alert.agent_id).role] += 1
            except UnknownAgent:
                pass
        cause = self.content.get(alert.cause_content_id)
        if cause is not None:
            # The cause of a real alert is a signature even if its own score was modest.
            sig = await self.book.promote(cause, alert.id)
            if sig and alert.feedback and (alert.id, alert.feedback.value) not in self._feedback_seen:
                self._feedback_seen.add((alert.id, alert.feedback.value))
                if alert.feedback is AlertFeedback.mark_benign:
                    await self.book.set_status(sig.id, SignatureStatus.benign)
                elif alert.feedback is AlertFeedback.confirm_attack:
                    await self.book.set_status(sig.id, SignatureStatus.confirmed)

    def summary(self) -> dict:
        sigs = self.book.all()
        techniques: Counter = Counter()
        for s in sigs:
            if s.status is not SignatureStatus.benign:
                for t in s.techniques:
                    techniques[t] += s.hits
        return {
            "signatures": {"total": len(sigs),
                           "confirmed": sum(s.status is SignatureStatus.confirmed for s in sigs),
                           "benign": sum(s.status is SignatureStatus.benign for s in sigs),
                           "agents_exposed": len({a for s in sigs for a in s.agents})},
            "top_attacked_roles": self.attacked_roles.most_common(5),
            "top_techniques": techniques.most_common(5),
            "top_blocked_destinations": self.blocked_destinations.most_common(5),
            "fleet_score": self.trend.query(1)["now"]["fleet_score"],
        }
