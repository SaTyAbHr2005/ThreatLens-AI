"""RegistryStore adapter: where identity state is persisted.

Two implementations with the same methods:
- MongoRegistryStore: MongoDB Atlas (deployed)
- MemoryRegistryStore: no database (unit tests, offline replay/eval runs)

Production swaps in Postgres behind the same methods (PRODUCTION.md §2).
"""

from datetime import datetime
from typing import Any

from pymongo.asynchronous.database import AsyncDatabase

from threatlens.core.db import C
from threatlens.core.schemas import Agent, AgentStatus, RoleAmendment, utcnow


class MemoryRegistryStore:
    def __init__(self) -> None:
        self.versions: list[dict[str, Any]] = []
        self.agents: dict[str, dict[str, Any]] = {}
        self.amendments: list[dict[str, Any]] = []
        self.revoked: dict[str, datetime] = {}

    async def load_contract_versions(self) -> list[dict[str, Any]]:
        return list(self.versions)

    async def save_contract_version(self, doc: dict[str, Any]) -> None:
        self.versions = [
            v for v in self.versions if (v["role"], v["version"]) != (doc["role"], doc["version"])
        ] + [doc]

    async def load_agents(self) -> list[Agent]:
        return [Agent.model_validate(a) for a in self.agents.values()]

    async def save_agent(self, agent: Agent) -> None:
        self.agents[agent.agent_id] = agent.model_dump(mode="json")

    async def set_agent_status(self, agent_id: str, status: AgentStatus, drift: float) -> None:
        self.agents[agent_id].update(status=status.value, drift=drift)

    async def load_amendments(self) -> list[RoleAmendment]:
        return [RoleAmendment.model_validate(a) for a in self.amendments]

    async def save_amendment(self, amendment: RoleAmendment) -> None:
        self.amendments.append(amendment.model_dump(mode="json"))

    async def load_revoked(self) -> dict[str, datetime]:
        now = utcnow()
        return {j: exp for j, exp in self.revoked.items() if exp > now}

    async def revoke(self, jti: str, expires_at: datetime) -> None:
        self.revoked[jti] = expires_at


class MongoRegistryStore:
    def __init__(self, db: AsyncDatabase) -> None:
        self.db = db

    async def load_contract_versions(self) -> list[dict[str, Any]]:
        return await self.db[C.roles].find({}, {"_id": 0}).to_list(None)

    async def save_contract_version(self, doc: dict[str, Any]) -> None:
        # Upsert: re-seeding a YAML version overwrites a copy whose signature no longer verifies.
        await self.db[C.roles].replace_one(
            {"role": doc["role"], "version": doc["version"]}, dict(doc), upsert=True
        )

    async def load_agents(self) -> list[Agent]:
        docs = await self.db[C.agents].find({}, {"_id": 0}).to_list(None)
        return [Agent.model_validate(d) for d in docs]

    async def save_agent(self, agent: Agent) -> None:
        await self.db[C.agents].replace_one(
            {"agent_id": agent.agent_id}, agent.model_dump(mode="json"), upsert=True
        )

    async def set_agent_status(self, agent_id: str, status: AgentStatus, drift: float) -> None:
        await self.db[C.agents].update_one(
            {"agent_id": agent_id}, {"$set": {"status": status.value, "drift": drift}}
        )

    async def load_amendments(self) -> list[RoleAmendment]:
        docs = await self.db[C.amendments].find({}, {"_id": 0}).sort("created_at", 1).to_list(None)
        return [RoleAmendment.model_validate(d) for d in docs]

    async def save_amendment(self, amendment: RoleAmendment) -> None:
        await self.db[C.amendments].insert_one(amendment.model_dump(mode="json"))

    async def load_revoked(self) -> dict[str, datetime]:
        docs = await self.db[C.revoked_tokens].find({"expires_at": {"$gt": utcnow()}}).to_list(None)
        return {d["jti"]: d["expires_at"] for d in docs}

    async def revoke(self, jti: str, expires_at: datetime) -> None:
        # expires_at stays a real datetime so the TTL index can expire the row.
        await self.db[C.revoked_tokens].update_one(
            {"jti": jti}, {"$set": {"jti": jti, "expires_at": expires_at}}, upsert=True
        )
