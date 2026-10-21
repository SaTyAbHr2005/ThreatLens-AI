"""HTTP API for M1. Mounted by the API app (M10)."""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from threatlens.core.http import bearer_token, registry, require_operator
from threatlens.core.schemas import Agent, RoleAmendment, RoleContract
from threatlens.core.security import InvalidToken

from .drafting import draft_contract
from .errors import (
    AgentExists,
    AgentQuarantined,
    DelegationDenied,
    IdentityError,
    InvalidAmendment,
    UnknownAgent,
    UnknownRole,
)
from .registry import IssuedToken, Registry

router = APIRouter(prefix="/v1", tags=["identity"])

_STATUS = {
    UnknownRole: status.HTTP_404_NOT_FOUND,
    UnknownAgent: status.HTTP_404_NOT_FOUND,
    AgentExists: status.HTTP_409_CONFLICT,
    InvalidAmendment: 422,
    DelegationDenied: status.HTTP_403_FORBIDDEN,
    AgentQuarantined: status.HTTP_423_LOCKED,
}


def _http(e: Exception) -> HTTPException:
    if isinstance(e, InvalidToken):
        return HTTPException(status.HTTP_401_UNAUTHORIZED, f"invalid token: {e}")
    code = next((c for t, c in _STATUS.items() if isinstance(e, t)), status.HTTP_400_BAD_REQUEST)
    return HTTPException(code, str(e) or type(e).__name__)


# ---------------------------------------------------------------- roles


class RoleDetail(BaseModel):
    contract: RoleContract
    amendments: list[RoleAmendment]


class AmendmentIn(BaseModel):
    changes: dict[str, Any]
    reason: str = Field(min_length=3)
    signer: str
    expires_at: datetime | None = None


class DraftIn(BaseModel):
    description: str = Field(min_length=10, max_length=2000)
    owner: str


class DraftOut(BaseModel):
    contract: RoleContract
    yaml: str
    source: str
    note: str | None


@router.get("/roles", response_model=list[RoleContract])
def list_roles(reg: Registry = Depends(registry)):
    return reg.roles()


@router.get("/roles/{role}", response_model=RoleDetail)
def get_role(role: str, reg: Registry = Depends(registry)):
    try:
        return RoleDetail(contract=reg.contract(role), amendments=reg.amendments(role))
    except IdentityError as e:
        raise _http(e) from e


@router.post("/roles/draft", response_model=DraftOut, dependencies=[Depends(require_operator)])
async def draft_role(body: DraftIn, request: Request):
    return await draft_contract(body.description, body.owner, getattr(request.app.state, "llm", None))


@router.post(
    "/roles/{role}/amendments",
    response_model=RoleAmendment,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_operator)],
)
async def amend_role(role: str, body: AmendmentIn, reg: Registry = Depends(registry)):
    try:
        return await reg.amend(role, body.changes, body.reason, body.signer, body.expires_at)
    except IdentityError as e:
        raise _http(e) from e


# ---------------------------------------------------------------- agents


class AgentIn(BaseModel):
    agent_id: str
    role: str
    owner: str


class AgentCreated(BaseModel):
    agent: Agent
    token: IssuedToken


class DelegateIn(BaseModel):
    callee_id: str


@router.get("/agents", response_model=list[Agent])
def list_agents(reg: Registry = Depends(registry)):
    return reg.agents()


@router.get("/agents/{agent_id}", response_model=Agent)
def get_agent(agent_id: str, reg: Registry = Depends(registry)):
    try:
        return reg.agent(agent_id)
    except IdentityError as e:
        raise _http(e) from e


@router.post(
    "/agents",
    response_model=AgentCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_operator)],
)
async def create_agent(body: AgentIn, reg: Registry = Depends(registry)):
    try:
        agent = await reg.create_agent(body.agent_id, body.role, body.owner)
        return AgentCreated(agent=agent, token=reg.issue_token(agent.agent_id))
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    except IdentityError as e:
        raise _http(e) from e


@router.post("/agents/{agent_id}/token", response_model=IssuedToken, dependencies=[Depends(require_operator)])
def issue_agent_token(agent_id: str, reg: Registry = Depends(registry)):
    """Used by the trusted agent runner to start an agent's session."""
    try:
        return reg.issue_token(agent_id)
    except IdentityError as e:
        raise _http(e) from e


@router.post("/agents/token/refresh", response_model=IssuedToken)
def refresh_token(token: str = Depends(bearer_token), reg: Registry = Depends(registry)):
    try:
        return reg.refresh(token)
    except (IdentityError, InvalidToken) as e:
        raise _http(e) from e


@router.post("/agents/{agent_id}/delegate", response_model=IssuedToken)
def delegate(agent_id: str, body: DelegateIn, token: str = Depends(bearer_token), reg: Registry = Depends(registry)):
    """The calling agent (bearer token) asks for an attenuated token for another agent."""
    try:
        caller = reg.verify(token)
        if caller.agent_id != agent_id:
            raise DelegationDenied("token does not belong to this agent")
        return reg.delegate(caller, body.callee_id)
    except (IdentityError, InvalidToken) as e:
        raise _http(e) from e
