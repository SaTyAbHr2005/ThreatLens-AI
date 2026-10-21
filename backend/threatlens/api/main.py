"""FastAPI entrypoint. M10 grows this; for now it only proves the M0 wiring
(settings, database, LLM router) works locally and on Render."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from threatlens import __version__
from threatlens.core import LLMRouter, bus, get_settings
from threatlens.core import db


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.db = db.connect(settings)
    if await db.ping(app.state.db):
        await db.ensure_indexes(app.state.db)
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


@app.get("/v1/health")
async def health() -> dict:
    db_ok = await db.ping(app.state.db)
    return {
        "status": "ok" if db_ok else "degraded",
        "version": __version__,
        "env": settings.env,
        "agent_mode": settings.agent_mode,
        "db": "ok" if db_ok else "unreachable",
        "llm": app.state.llm.status(),
    }
