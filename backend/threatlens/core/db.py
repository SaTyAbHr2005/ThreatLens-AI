"""MongoDB access via PyMongo's native async client.

Collections and their indexes live here so every module agrees on names and
retention. Raw events expire after 7 days to stay inside Atlas M0's 512 MB.
"""

from pymongo import ASCENDING, DESCENDING, AsyncMongoClient, IndexModel
from pymongo.asynchronous.database import AsyncDatabase

from .config import Settings, get_settings

DAY = 24 * 3600


class C:
    """Collection names."""

    events = "events"
    agent_minutely = "agent_minutely"
    agents = "agents"
    roles = "roles"
    amendments = "amendments"
    content_items = "content_items"
    signatures = "signatures"
    baselines = "baselines"
    alerts = "alerts"
    decisions = "decisions"
    arena_runs = "arena_runs"
    eval_runs = "eval_runs"
    analysts = "analysts"
    login_events = "login_events"
    revoked_tokens = "revoked_tokens"


INDEXES: dict[str, list[IndexModel]] = {
    C.events: [
        IndexModel([("agent_id", ASCENDING), ("ts", DESCENDING)]),
        IndexModel([("session_id", ASCENDING), ("ts", ASCENDING)]),
        IndexModel([("ts", ASCENDING)], expireAfterSeconds=7 * DAY, name="ttl_ts"),
    ],
    C.agent_minutely: [
        IndexModel([("agent_id", ASCENDING), ("minute", ASCENDING)], unique=True),
        IndexModel([("minute", ASCENDING)], expireAfterSeconds=90 * DAY, name="ttl_minute"),
    ],
    C.agents: [IndexModel([("agent_id", ASCENDING)], unique=True)],
    C.roles: [IndexModel([("role", ASCENDING), ("version", DESCENDING)], unique=True)],
    C.amendments: [IndexModel([("role", ASCENDING), ("created_at", DESCENDING)])],
    C.content_items: [
        IndexModel([("sha256", ASCENDING)]),
        IndexModel([("created_at", ASCENDING)], expireAfterSeconds=30 * DAY, name="ttl_created"),
    ],
    C.signatures: [IndexModel([("sha256", ASCENDING)], unique=True), IndexModel([("simhash", ASCENDING)])],
    C.alerts: [
        IndexModel([("status", ASCENDING), ("risk", DESCENDING)]),
        IndexModel([("agent_id", ASCENDING), ("ts", DESCENDING)]),
    ],
    C.decisions: [IndexModel([("agent_id", ASCENDING), ("ts", DESCENDING)])],
    C.analysts: [IndexModel([("email", ASCENDING)], unique=True)],
    C.login_events: [IndexModel([("email", ASCENDING), ("ts", DESCENDING)])],
    # A revoked token only needs remembering until it would have expired anyway.
    C.revoked_tokens: [
        IndexModel([("jti", ASCENDING)], unique=True),
        IndexModel([("expires_at", ASCENDING)], expireAfterSeconds=0, name="ttl_expiry"),
    ],
}

_client: AsyncMongoClient | None = None


def connect(settings: Settings | None = None) -> AsyncDatabase:
    """Create (once) and return the database handle. The client connects lazily."""
    global _client
    settings = settings or get_settings()
    if _client is None:
        _client = AsyncMongoClient(
            settings.mongo_uri, tz_aware=True, serverSelectionTimeoutMS=settings.mongo_timeout_ms
        )
    return _client[settings.mongo_db]


def get_db() -> AsyncDatabase:
    return connect()


async def ensure_indexes(db: AsyncDatabase) -> None:
    for name, indexes in INDEXES.items():
        await db[name].create_indexes(indexes)


async def ping(db: AsyncDatabase) -> bool:
    try:
        await db.command("ping")
        return True
    except Exception:
        return False


async def close() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None
