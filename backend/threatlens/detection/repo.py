"""Persist baselines to MongoDB Atlas, so learning survives Render restarts and sleeps."""

import asyncio
import logging

from pymongo.asynchronous.database import AsyncDatabase

from threatlens.core.db import C
from threatlens.core.schemas import utcnow

from .baselines import BaselineStore

log = logging.getLogger(__name__)
DOC_ID = "snapshot"


async def load_baselines(db: AsyncDatabase) -> BaselineStore:
    doc = await db[C.baselines].find_one({"_id": DOC_ID})
    if not doc:
        return BaselineStore()
    try:
        return BaselineStore.restore(doc["data"])
    except (KeyError, TypeError, ValueError):
        log.exception("stored baselines are unreadable; starting fresh")
        return BaselineStore()


async def save_baselines(db: AsyncDatabase, store: BaselineStore) -> None:
    await db[C.baselines].replace_one(
        {"_id": DOC_ID}, {"_id": DOC_ID, "data": store.snapshot(), "updated_at": utcnow()}, upsert=True
    )
    store.dirty = False


async def persist_periodically(db: AsyncDatabase, store: BaselineStore, every_s: float = 120) -> None:
    while True:
        await asyncio.sleep(every_s)
        if store.dirty:
            try:
                await save_baselines(db, store)
            except Exception:
                log.exception("saving baselines failed; will retry")
