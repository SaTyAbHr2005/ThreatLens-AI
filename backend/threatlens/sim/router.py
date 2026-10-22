"""HTTP API for M8: run demo scenarios and the Red Team test harness."""

from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from threatlens.core.http import require_operator

from .encode import TECHNIQUES
from .redteam import RedTeamResult, run_redteam
from .runner import ScenarioResult
from .scenarios import META, run_scenario

router = APIRouter(prefix="/v1/sim", tags=["simulator"], dependencies=[Depends(require_operator)])


class ScenarioInfo(BaseModel):
    id: str
    name: str
    challenge: str
    kind: Literal["attack", "control"]


class FollowUp(BaseModel):
    tool: str
    args: dict = Field(default_factory=dict)


class RedTeamIn(BaseModel):
    instruction: str = Field(min_length=3, max_length=1000)
    technique: Literal["zero_width", "unicode_tags", "white_text_pdf", "base64", "visible"] = "zero_width"
    target_role: str = "procurement"
    follow_up: FollowUp | None = None


def _runner(request: Request):
    return request.app.state.sim_runner


def _serialize(result: ScenarioResult) -> dict:
    d = asdict(result)
    d["alert"] = result.alert.model_dump(mode="json") if result.alert else None
    return d


@router.get("/scenarios", response_model=list[ScenarioInfo])
def list_scenarios():
    return [ScenarioInfo(id=sid, name=name, challenge=challenge,
                         kind="attack" if sid.startswith("A") else "control")
            for sid, (name, challenge) in META.items()]


@router.get("/techniques", response_model=list[str])
def list_techniques():
    return list(TECHNIQUES)


@router.post("/scenarios/{scenario_id}/run")
async def run(scenario_id: str, request: Request, mode: Literal["replay", "llm"] = "replay"):
    try:
        result = await run_scenario(_runner(request), scenario_id, mode)
    except KeyError:
        raise HTTPException(404, f"no scenario {scenario_id.upper()}") from None
    return _serialize(result)


@router.post("/redteam", response_model=RedTeamResult)
async def redteam(body: RedTeamIn, request: Request):
    return await run_redteam(_runner(request), body.instruction, body.technique, body.target_role,
                             body.follow_up.model_dump() if body.follow_up else None)
