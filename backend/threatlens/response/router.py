"""HTTP API for M6: approvals, containment, analyst feedback, audit log, reports."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from threatlens.core.http import bearer_token, require_operator
from threatlens.core.schemas import Alert, AlertFeedback, Approval, ApprovalStatus, Decision, RoleAmendment
from threatlens.core.security import InvalidToken
from threatlens.identity import IdentityError, InvalidAmendment, UnknownAgent

from .approvals import ApprovalError
from .orchestrator import NothingToAmend, ResponseOrchestrator
from .report import dossier_markdown, ocsf_finding

router = APIRouter(prefix="/v1", tags=["response"])
operator = [Depends(require_operator)]


def orchestrator(request: Request) -> ResponseOrchestrator:
    return request.app.state.response


class ApprovalDecisionIn(BaseModel):
    approve: bool
    actor: str = Field(min_length=3, max_length=200)


class ContainmentIn(BaseModel):
    action: Literal["release", "restrict", "step_up", "isolate"]
    reason: str = Field(min_length=3, max_length=1000)
    actor: str = Field(min_length=3, max_length=200)


class FeedbackIn(BaseModel):
    feedback: AlertFeedback
    reason: str = Field("", max_length=1000)
    actor: str = Field(min_length=3, max_length=200, description="for approve_as_amendment: the signer's email")


class FeedbackOut(BaseModel):
    alert: Alert
    decision: Decision | None = None
    amendment: RoleAmendment | None = None


# ---------------------------------------------------------------- approvals


@router.get("/approvals", response_model=list[Approval], dependencies=operator)
def list_approvals(status: ApprovalStatus | None = None, o: ResponseOrchestrator = Depends(orchestrator)):
    return o.approvals.list(status)


@router.post("/approvals/{approval_id}", response_model=Approval, dependencies=operator)
async def decide_approval(approval_id: str, body: ApprovalDecisionIn, request: Request,
                          o: ResponseOrchestrator = Depends(orchestrator)):
    try:
        return await o.approvals.decide(approval_id, body.approve, body.actor, request.app.state.gateway)
    except ApprovalError as e:
        raise HTTPException(409 if "already" in str(e) else 404, str(e)) from e


@router.get("/gateway/approvals/{approval_id}", response_model=Approval)
def agent_approval_status(approval_id: str, request: Request, token: str = Depends(bearer_token),
                          o: ResponseOrchestrator = Depends(orchestrator)):
    """The agent that asked polls here to learn the outcome (and get the result if approved)."""
    try:
        claims = request.app.state.registry.verify(token)
    except (InvalidToken, IdentityError) as e:
        raise HTTPException(401, "invalid agent token") from e
    a = o.approvals.get(approval_id)
    if a is None or a.agent_id != claims.agent_id:
        raise HTTPException(404, "no such approval")
    return a


# ---------------------------------------------------------------- containment & feedback


@router.post("/agents/{agent_id}/containment", response_model=Decision, dependencies=operator)
async def contain(agent_id: str, body: ContainmentIn, o: ResponseOrchestrator = Depends(orchestrator)):
    try:
        return await o.apply(agent_id, body.action, body.reason, body.actor)
    except UnknownAgent as e:
        raise HTTPException(404, "unknown agent") from e


@router.post("/alerts/{alert_id}/feedback", response_model=FeedbackOut, dependencies=operator)
async def feedback(alert_id: str, body: FeedbackIn, o: ResponseOrchestrator = Depends(orchestrator)):
    try:
        return FeedbackOut(**await o.feedback(alert_id, body.feedback, body.actor, body.reason))
    except KeyError as e:
        raise HTTPException(404, "no such alert") from e
    except (NothingToAmend, InvalidAmendment) as e:
        raise HTTPException(422, str(e)) from e


@router.get("/decisions", response_model=list[Decision], dependencies=operator)
async def decisions(agent_id: str | None = None, limit: int = 100, o: ResponseOrchestrator = Depends(orchestrator)):
    return await o.decisions.list(agent_id, min(max(limit, 1), 500))


# ---------------------------------------------------------------- reports


async def _alert(alert_id: str, o: ResponseOrchestrator) -> Alert:
    alert = o.fusion.live_alert(alert_id) or await o.fusion.alerts.get(alert_id)
    if alert is None:
        raise HTTPException(404, "no such alert")
    return alert


@router.get("/alerts/{alert_id}/dossier", response_class=PlainTextResponse, dependencies=operator)
async def dossier(alert_id: str, o: ResponseOrchestrator = Depends(orchestrator)):
    alert = await _alert(alert_id, o)
    decisions = [d for d in await o.decisions.list(alert.agent_id, 500) if d.alert_id in (None, alert.id)]
    events = []
    if o.gateway:
        wanted = set(alert.timeline)
        events = sorted((e for s in o.gateway.sessions.for_agent(alert.agent_id) for e in s.history if e.id in wanted),
                        key=lambda e: e.ts)
    return PlainTextResponse(dossier_markdown(alert, sorted(decisions, key=lambda d: d.ts), events),
                             media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="{alert.id}.md"'})


@router.get("/alerts/{alert_id}/ocsf", dependencies=operator)
async def ocsf(alert_id: str, o: ResponseOrchestrator = Depends(orchestrator)):
    return ocsf_finding(await _alert(alert_id, o))
