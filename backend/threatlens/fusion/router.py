"""HTTP API for M5: alerts and per-agent risk."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from threatlens.core.http import require_operator
from threatlens.core.schemas import Alert, AlertStatus, DecisionType
from threatlens.identity import UnknownAgent

router = APIRouter(prefix="/v1", tags=["alerts"], dependencies=[Depends(require_operator)])


class RiskPoint(BaseModel):
    ts: str
    event_id: str
    tool: str
    resource: str | None
    risk: float | None
    decision: DecisionType | None


class AgentRisk(BaseModel):
    agent_id: str
    status: str
    drift: float
    trust: float
    open_alerts: int
    recent: list[RiskPoint]  # newest last, from live sessions


@router.get("/alerts", response_model=list[Alert])
async def list_alerts(request: Request, status: AlertStatus | None = None, agent_id: str | None = None,
                      limit: int = Query(50, ge=1, le=500)):
    return await request.app.state.fusion.alerts.list(status, agent_id, limit)


@router.get("/alerts/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str, request: Request):
    alert = await request.app.state.fusion.alerts.get(alert_id)
    if alert is None:
        raise HTTPException(404, "no such alert")
    return alert


@router.get("/agents/{agent_id}/risk", response_model=AgentRisk)
async def agent_risk(agent_id: str, request: Request, limit: int = Query(100, ge=1, le=500)):
    try:
        agent = request.app.state.registry.agent(agent_id)
    except UnknownAgent as e:
        raise HTTPException(404, "unknown agent") from e
    events = sorted(
        (e for s in request.app.state.gateway.sessions.for_agent(agent_id) for e in s.history),
        key=lambda e: e.ts,
    )[-limit:]
    open_alerts = await request.app.state.fusion.alerts.list(AlertStatus.open, agent_id, 500)
    return AgentRisk(
        agent_id=agent_id,
        status=agent.status.value,
        drift=agent.drift,
        trust=agent.trust,
        open_alerts=len(open_alerts),
        recent=[RiskPoint(ts=e.ts.isoformat(), event_id=e.id, tool=e.action.tool, resource=e.action.resource,
                          risk=e.risk, decision=e.decision) for e in events],
    )
