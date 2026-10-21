"""In-process async pub/sub.

`publish` never blocks the caller: handlers run as background tasks, so the
gateway's hot path doesn't wait on the WebSocket hub or the intel module. A
failing handler is logged and never affects other handlers or the publisher.

ponytail: single-process only. In production this is a Kafka topic (see
PRODUCTION.md), behind the same publish/subscribe calls.
"""

import asyncio
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger(__name__)

Handler = Callable[[Any], Awaitable[None]]


class Topics:
    action_scored = "action.scored"
    alert_raised = "alert.raised"
    containment_changed = "containment.changed"
    content_scanned = "content.scanned"
    arena_progress = "arena.progress"


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, list[Handler]] = defaultdict(list)
        self._pending: set[asyncio.Task] = set()

    def subscribe(self, topic: str, handler: Handler) -> Callable[[], None]:
        self._subs[topic].append(handler)
        return lambda: self._subs[topic].remove(handler)

    def publish(self, topic: str, payload: Any) -> None:
        for handler in list(self._subs.get(topic, ())):
            task = asyncio.create_task(self._run(topic, handler, payload))
            self._pending.add(task)
            task.add_done_callback(self._pending.discard)

    async def drain(self) -> None:
        """Wait for every in-flight handler (tests and graceful shutdown)."""
        while self._pending:
            await asyncio.gather(*list(self._pending))

    @staticmethod
    async def _run(topic: str, handler: Handler, payload: Any) -> None:
        try:
            await handler(payload)
        except Exception:
            log.exception("bus handler %r failed on %s", handler, topic)


bus = EventBus()
