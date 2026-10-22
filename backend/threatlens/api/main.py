"""FastAPI entrypoint (M10). Wires the modules together and mounts their routers."""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from threatlens import __version__
from threatlens.core import LLMRouter, Topics, bus, get_settings
from threatlens.core import db
from threatlens.detection import (
    BaselineStore,
    Detector,
    load_baselines,
    make_embedder,
    persist_periodically,
    save_baselines,
)
from threatlens.gateway import Catalog, Gateway, HttpToolConnector, UnconfiguredConnector, attach_mongo_sinks
from threatlens.gateway.router import router as gateway_router
from threatlens.identity import MemoryRegistryStore, MongoRegistryStore, Registry
from threatlens.identity.router import router as identity_router
from threatlens.scanner import ContentForensics, PromptGuard
from threatlens.scanner.router import router as forensics_router

# Send ThreatLens warnings (unreachable DB, tampered contracts, ...) to stdout,
# which Docker and Render's log viewer capture. Uvicorn only configures its own loggers.
logging.basicConfig(level=logging.INFO, format="%(levelname)s:     %(name)s: %(message)s")
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
    persist = db_ok or settings.env == "prod"
    if persist:
        store = MongoRegistryStore(app.state.db)
    else:
        log.warning("MongoDB unreachable: identity state and events are in memory only and will be lost on restart")
        store = MemoryRegistryStore()
    app.state.registry = Registry(store, settings)
    await app.state.registry.load()

    catalog = Catalog.load(settings.catalog_dir)
    prompt_guard = (
        PromptGuard(settings.groq_api_key, settings.prompt_guard_model)
        if settings.groq_api_key and settings.prompt_guard_model
        else None
    )
    app.state.forensics = ContentForensics(prompt_guard, internal_domains=tuple(catalog.internal_domains))

    baselines = await load_baselines(app.state.db) if db_ok else BaselineStore()
    embedder = make_embedder(settings.embedding_backend, settings.embedding_model, settings.models_dir)
    app.state.detector = Detector(app.state.registry, catalog, embedder, baselines)

    connector = HttpToolConnector(settings.tools_base_url) if settings.tools_base_url else UnconfiguredConnector()
    app.state.gateway = Gateway(
        app.state.registry, catalog, connector,
        scanner=app.state.forensics, scorer=app.state.detector, settings=settings,
    )
    unsubscribe = attach_mongo_sinks(bus, app.state.db) if persist else []
    unsubscribe.append(bus.subscribe(Topics.action_scored, app.state.detector.observe))
    saver = asyncio.create_task(persist_periodically(app.state.db, baselines)) if db_ok else None

    app.state.llm = LLMRouter.from_settings(settings)
    yield
    await bus.drain()
    for off in unsubscribe:
        off()
    if saver:
        saver.cancel()
        if baselines.dirty:
            await save_baselines(app.state.db, baselines)
    await connector.aclose()
    await app.state.forensics.aclose()
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
app.include_router(gateway_router)
app.include_router(forensics_router)


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
        "tools": len(app.state.gateway.catalog.tools),
        "tool_backend": "configured" if settings.tools_base_url else "not configured",
        "content_scanner": "prompt_guard+heuristics" if app.state.forensics.prompt_guard else "heuristics",
        "embedder": app.state.detector.embedder.name,
        "baselines": {"agents": len(app.state.detector.store.agents), "roles": len(app.state.detector.store.roles)},
        "llm": app.state.llm.status(),
    }
