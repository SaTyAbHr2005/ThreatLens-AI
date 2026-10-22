"""HTTP API for M7: fleet trend, signature feed, leaderboards, LLM Susceptibility Arena."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from threatlens.core.http import require_operator

from .arena import ArenaRun
from .signatures import Signature, SignatureStatus

router = APIRouter(prefix="/v1", tags=["intel"], dependencies=[Depends(require_operator)])


class StatusIn(BaseModel):
    status: SignatureStatus
    actor: str = Field(min_length=3, max_length=200)


class ArenaIn(BaseModel):
    signature_id: str | None = None
    content_id: str | None = None
    instruction: str | None = Field(None, max_length=1000)


@router.get("/intel/trend")
def trend(request: Request, minutes: int = Query(60, ge=1, le=360)):
    return request.app.state.intel.trend.query(minutes)


@router.get("/intel/summary")
def summary(request: Request):
    return request.app.state.intel.summary()


@router.get("/intel/signatures", response_model=list[Signature])
def signatures(request: Request, status: SignatureStatus | None = None):
    return request.app.state.intel.book.all(status)


@router.get("/intel/signatures/{sig_id}", response_model=Signature)
def signature(sig_id: str, request: Request):
    s = request.app.state.intel.book.get(sig_id)
    if s is None:
        raise HTTPException(404, "no such signature")
    return s


@router.post("/intel/signatures/{sig_id}/status", response_model=Signature)
async def set_signature_status(sig_id: str, body: StatusIn, request: Request):
    s = await request.app.state.intel.book.set_status(sig_id, body.status)
    if s is None:
        raise HTTPException(404, "no such signature")
    return s


@router.get("/arena/models")
def arena_models(request: Request) -> list[str]:
    return request.app.state.arena.models()


@router.post("/arena/run", response_model=ArenaRun, status_code=202)
async def arena_run(body: ArenaIn, request: Request):
    """Replay a captured instruction against every configured free model (sandboxed tools).
    Async on purpose: the run is started as a task on the server's event loop."""
    intel, arena = request.app.state.intel, request.app.state.arena
    if not arena.models():
        raise HTTPException(503, "no LLM providers configured")
    if body.signature_id:
        s = intel.book.get(body.signature_id)
        if s is None:
            raise HTTPException(404, "no such signature")
        return arena.start(s.instruction, f"signature {s.id} ({s.first_source})")
    if body.content_id:
        item = intel.content.get(body.content_id)
        if item is None or not (item.instruction or item.decoded_text):
            raise HTTPException(404, "no such content, or it carries no instruction")
        return arena.start(item.instruction or item.decoded_text[:500], item.source)
    if body.instruction:
        return arena.start(body.instruction, "custom")
    raise HTTPException(422, "send signature_id, content_id or instruction")


@router.get("/arena/runs", response_model=list[ArenaRun])
def arena_runs(request: Request):
    return request.app.state.arena.list()


@router.get("/arena/runs/{run_id}", response_model=ArenaRun)
def arena_get(run_id: str, request: Request):
    run = request.app.state.arena.get(run_id)
    if run is None:
        raise HTTPException(404, "no such run")
    return run
