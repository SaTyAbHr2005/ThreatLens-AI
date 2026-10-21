"""EventSink adapter: persist what the gateway publishes.

MongoDB Atlas here; Kafka → ClickHouse in production (PRODUCTION.md §2).
Timestamps stay real datetimes so the TTL indexes can expire old rows.
"""

from collections.abc import Callable

from pymongo.asynchronous.database import AsyncDatabase

from threatlens.core.bus import EventBus, Topics
from threatlens.core.db import C
from threatlens.core.schemas import ActionEvent, ContentItem


def attach_mongo_sinks(bus: EventBus, db: AsyncDatabase) -> list[Callable[[], None]]:
    """Subscribe the sinks; returns unsubscribe callables for shutdown."""

    async def save_event(event: ActionEvent) -> None:
        doc = event.model_dump(mode="json")
        doc["_id"] = doc.pop("id")
        doc["ts"] = event.ts
        await db[C.events].insert_one(doc)

    async def save_content(item: ContentItem) -> None:
        doc = item.model_dump(mode="json")
        doc["_id"] = doc.pop("id")
        doc["created_at"] = item.created_at
        await db[C.content_items].insert_one(doc)

    return [
        bus.subscribe(Topics.action_scored, save_event),
        bus.subscribe(Topics.content_scanned, save_content),
    ]
