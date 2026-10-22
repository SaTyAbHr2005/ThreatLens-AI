"""HTTP API for M9: the latest evaluation results, and a smaller re-run on demand."""

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from threatlens.core.config import get_settings
from threatlens.core.http import require_operator

from .run import evaluate, load_latest, save

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/eval", tags=["evaluation"])
_task: asyncio.Task | None = None


@router.get("/latest")
def latest():
    """Measured numbers only: 404 until an evaluation has been run."""
    result = load_latest(get_settings().eval_results_path)
    if result is None:
        raise HTTPException(404, "no evaluation results yet; run python -m threatlens.evaluation.run")
    return {**result, "running": bool(_task and not _task.done())}


@router.post("/run", status_code=202, dependencies=[Depends(require_operator)])
async def run(request: Request, benign: int = Query(20, ge=5, le=100), attacks: int = Query(10, ge=5, le=50),
              seed: int = 7):
    """Re-run in the background (sized for the free tier); results replace /latest when done."""
    global _task
    if _task and not _task.done():
        raise HTTPException(409, "an evaluation is already running")
    settings = get_settings()

    async def job():
        try:
            # Reuse the loaded embedding model instead of loading a second copy.
            result = await evaluate(settings, embedder=request.app.state.detector.embedder, seed=seed,
                                    benign_per_role=benign, attacks_per_scenario=attacks)
            save(result, settings.eval_results_path)
        except Exception:
            log.exception("evaluation run failed")

    _task = asyncio.create_task(job())
    return {"status": "started", "benign_per_role": benign, "attacks_per_scenario": attacks}
