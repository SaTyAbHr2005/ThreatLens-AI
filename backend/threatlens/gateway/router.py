"""HTTP API for M2: the endpoints every agent calls."""

import base64
import binascii
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from threatlens.core.http import bearer_token
from threatlens.core.schemas import Carrier, ContentItem, DecisionType, RuntimeFingerprint
from threatlens.core.security import InvalidToken
from threatlens.identity import IdentityError

from .catalog import BadToolArgs
from .service import Gateway, GatewayResult, ToolCallFailed

router = APIRouter(prefix="/v1/gateway", tags=["gateway"])

MAX_ARGS_BYTES = 256_000
SESSION_ID = r"^[A-Za-z0-9_-]{1,64}$"

STATUS_BY_DECISION = {
    DecisionType.allow: 200,
    DecisionType.allow_logged: 200,
    DecisionType.require_approval: 202,
    DecisionType.deny: 403,
    DecisionType.quarantine: 423,
}


class ToolCallIn(BaseModel):
    session_id: str = Field(pattern=SESSION_ID)
    tool: str = Field(min_length=1, max_length=100)
    args: dict[str, Any] = Field(default_factory=dict)
    host: str | None = Field(None, max_length=200)  # the agent's runtime host
    pid: int | None = None


class ContentIn(BaseModel):
    session_id: str = Field(pattern=SESSION_ID)
    source: str = Field(min_length=1, max_length=500)
    carrier: Carrier = "text"
    text: str = Field("", max_length=2_000_000)
    content_b64: str | None = Field(None, max_length=2_700_000, description="original bytes, e.g. a PDF")
    media_type: str | None = Field(None, max_length=100)


def gateway(request: Request) -> Gateway:
    return request.app.state.gateway


def _auth_error(e: Exception) -> HTTPException:
    return HTTPException(401, f"invalid agent token: {e}" if isinstance(e, InvalidToken) else "unknown agent")


@router.post(
    "/tool-call",
    response_model=GatewayResult,
    responses={202: {"model": GatewayResult}, 403: {"model": GatewayResult}, 423: {"model": GatewayResult}},
)
async def tool_call(
    body: ToolCallIn, request: Request, token: str = Depends(bearer_token), gw: Gateway = Depends(gateway)
):
    """Every agent tool call goes through here. The status code mirrors the decision."""
    if len(json.dumps(body.args, default=str)) > MAX_ARGS_BYTES:
        raise HTTPException(413, f"tool arguments are larger than {MAX_ARGS_BYTES} bytes")
    runtime = RuntimeFingerprint(
        host=body.host,
        ip=request.client.host if request.client else None,
        sdk=request.headers.get("x-threatlens-sdk"),
        pid=body.pid,
    )
    try:
        result = await gw.tool_call(token, body.session_id, body.tool, body.args, runtime)
    except (InvalidToken, IdentityError) as e:
        raise _auth_error(e) from e
    except BadToolArgs as e:
        raise HTTPException(422, str(e)) from e
    except ToolCallFailed as e:
        # The gateway's verdict (decision, risk, tier) still matters even though the tool failed.
        return JSONResponse(status_code=502, content={**e.result.model_dump(mode="json"), "detail": str(e)})
    return JSONResponse(status_code=STATUS_BY_DECISION[result.decision], content=result.model_dump(mode="json"))


@router.post("/content", response_model=ContentItem, status_code=201)
async def register_content(body: ContentIn, token: str = Depends(bearer_token), gw: Gateway = Depends(gateway)):
    """Report untrusted content the agent read outside a tool call. It becomes provenance taint."""
    if not body.text and not body.content_b64:
        raise HTTPException(422, "send text or content_b64")
    try:
        raw = base64.b64decode(body.content_b64, validate=True) if body.content_b64 else None
    except (binascii.Error, ValueError) as e:
        raise HTTPException(422, "content_b64 is not valid base64") from e
    try:
        return await gw.register_content(
            token, body.session_id, body.source, body.carrier, body.text, raw, body.media_type
        )
    except (InvalidToken, IdentityError) as e:
        raise _auth_error(e) from e
    except BadToolArgs as e:
        raise HTTPException(413, str(e)) from e
