"""FastAPI entrypoint (M10). Wires the modules together and mounts their routers."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from threatlens import __version__
from threatlens.core import LLMRouter, bus, get_settings
from threatlens.core import db
from threatlens.identity import MemoryRegistryStore, MongoRegistryStore, Registry
from threatlens.identity.router import router as identity_router

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.db = db.connect(settings)
    db_ok = await db.ping(app.state.db)
    if db_ok:
        await db.ensure_indexes(app.state.db)

    # Production always persists to Atlas (startup fails loudly if it can't).
    # dev/test fall back to memory so the API still runs without a database.
    if db_ok or settings.env == "prod":
        store = MongoRegistryStore(app.state.db)
    else:
        log.warning("MongoDB unreachable: identity state is in memory only and will be lost on restart")
        store = MemoryRegistryStore()
    app.state.registry = Registry(store, settings)
    await app.state.registry.load()

    app.state.llm = LLMRouter.from_settings(settings)
    yield
    await bus.drain()
    await app.state.llm.aclose()
    await db.close()


settings = get_settings()
app = FastAPI(title="ThreatLens AI", version=__version__, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(identity_router)


@app.get("/v1/health")
async def health() -> dict:
    db_ok = await db.ping(app.state.db)
    return {
        "status": "ok" if db_ok else "degraded",
        "version": __version__,
        "env": settings.env,
        "agent_mode": settings.agent_mode,
        "db": "ok" if db_ok else "unreachable",
        "roles": len(app.state.registry.roles()),
        "agents": len(app.state.registry.agents()),
        "llm": app.state.llm.status(),
    }
