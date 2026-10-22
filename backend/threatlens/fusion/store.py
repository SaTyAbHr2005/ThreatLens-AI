"""AlertStore adapter: MongoDB Atlas (deployed) or memory (tests, offline)."""

from pymongo import DESCENDING
from pymongo.asynchronous.database import AsyncDatabase

from threatlens.core.db import C
from threatlens.core.schemas import Alert, AlertStatus


class MemoryAlertStore:
    def __init__(self) -> None:
        self.alerts: dict[str, Alert] = {}

    async def save(self, alert: Alert) -> None:
        self.alerts[alert.id] = alert.model_copy(deep=True)

    async def get(self, alert_id: str) -> Alert | None:
        a = self.alerts.get(alert_id)
        return a.model_copy(deep=True) if a else None

    async def list(self, status: AlertStatus | None = None, agent_id: str | None = None, limit: int = 50) -> list[Alert]:
        items = [a for a in self.alerts.values()
                 if (status is None or a.status is status) and (agent_id is None or a.agent_id == agent_id)]
        return sorted(items, key=lambda a: a.ts, reverse=True)[:limit]


class MongoAlertStore:
    def __init__(self, db: AsyncDatabase) -> None:
        self.col = db[C.alerts]

    async def save(self, alert: Alert) -> None:
        doc = alert.model_dump(mode="json")
        doc["_id"] = doc.pop("id")
        doc["ts"], doc["updated_at"] = alert.ts, alert.updated_at
        await self.col.replace_one({"_id": doc["_id"]}, doc, upsert=True)

    async def get(self, alert_id: str) -> Alert | None:
        doc = await self.col.find_one({"_id": alert_id})
        return _from_doc(doc) if doc else None

    async def list(self, status: AlertStatus | None = None, agent_id: str | None = None, limit: int = 50) -> list[Alert]:
        q: dict = {}
        if status:
            q["status"] = status.value
        if agent_id:
            q["agent_id"] = agent_id
        docs = await self.col.find(q).sort("ts", DESCENDING).limit(limit).to_list(None)
        return [_from_doc(d) for d in docs]


def _from_doc(doc: dict) -> Alert:
    doc = dict(doc)
    doc["id"] = doc.pop("_id")
    return Alert.model_validate(doc)
