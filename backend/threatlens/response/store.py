"""Append-only audit log of every containment decision (who, what, when, why)."""

from pymongo import DESCENDING
from pymongo.asynchronous.database import AsyncDatabase

from threatlens.core.db import C
from threatlens.core.schemas import Decision


class MemoryDecisionStore:
    def __init__(self) -> None:
        self.items: list[Decision] = []

    async def add(self, d: Decision) -> None:
        self.items.append(d)

    async def list(self, agent_id: str | None = None, limit: int = 100) -> list[Decision]:
        items = [d for d in self.items if agent_id is None or d.agent_id == agent_id]
        return sorted(items, key=lambda d: d.ts, reverse=True)[:limit]


class MongoDecisionStore:
    def __init__(self, db: AsyncDatabase) -> None:
        self.col = db[C.decisions]

    async def add(self, d: Decision) -> None:
        doc = d.model_dump(mode="json")
        doc["_id"] = doc.pop("id")
        doc["ts"] = d.ts
        await self.col.insert_one(doc)  # insert only: decisions are never edited

    async def list(self, agent_id: str | None = None, limit: int = 100) -> list[Decision]:
        q = {"agent_id": agent_id} if agent_id else {}
        docs = await self.col.find(q).sort("ts", DESCENDING).limit(limit).to_list(None)
        out = []
        for doc in docs:
            doc["id"] = doc.pop("_id")
            out.append(Decision.model_validate(doc))
        return out
