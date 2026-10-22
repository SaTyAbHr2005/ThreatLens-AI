"""Per-agent, per-minute risk aggregates for the drift timeline (kept 90 days; raw events only 7)."""

from collections.abc import Callable

from pymongo.asynchronous.database import AsyncDatabase

from threatlens.core.bus import EventBus, Topics
from threatlens.core.db import C
from threatlens.core.schemas import ActionEvent
from threatlens.identity import Registry, UnknownAgent


def attach_minute_sink(bus: EventBus, db: AsyncDatabase, registry: Registry) -> Callable[[], None]:
    async def on_event(e: ActionEvent) -> None:
        if e.risk is None:
            return
        try:
            drift = registry.agent(e.agent_id).drift
        except UnknownAgent:
            return
        await db[C.agent_minutely].update_one(
            {"agent_id": e.agent_id, "minute": e.ts.replace(second=0, microsecond=0)},
            {"$inc": {"count": 1, "alerting": 1 if e.alert_id else 0},
             "$max": {"max_risk": e.risk}, "$set": {"drift": drift}},
            upsert=True,
        )

    return bus.subscribe(Topics.action_scored, on_event)
