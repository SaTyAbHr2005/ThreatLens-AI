"""ThreatLens client for agents: send every tool call through the gateway.

    client = ThreatLensClient("https://threatlens-api.onrender.com", token)
    prices = client.call("supplier_db.query", table="prices")

Depends only on httpx, so it drops into any agent framework (call it from a
tool function or a framework callback hook).
"""

import base64
import json
import os
import socket
import time
import uuid
from typing import Any

import httpx

from .errors import ActionDenied, AgentQuarantined, ApprovalRequired, AuthError, ThreatLensError, ToolFailed

SDK_VERSION = "threatlens-py/0.1.0"
REFRESH_MARGIN_S = 60


def _claims(token: str) -> dict[str, Any]:
    """Read (not verify) the token payload; the gateway does the verifying."""
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return {}


def _raise_for(r: httpx.Response) -> dict[str, Any]:
    try:
        body = r.json()
    except ValueError:
        body = {"detail": r.text[:200]}
    if r.status_code in (200, 201):
        return body
    message = body.get("reason") or body.get("detail") or f"HTTP {r.status_code}"
    error = {
        401: AuthError,
        202: ApprovalRequired,
        403: ActionDenied,
        423: AgentQuarantined,
        502: ToolFailed,
        503: ToolFailed,
    }.get(r.status_code, ThreatLensError)
    raise error(str(message), status=r.status_code, response=body)


class _Base:
    def __init__(self, api_url: str, token: str, session_id: str | None, host: str | None):
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.session_id = session_id or uuid.uuid4().hex[:24]
        self.host = host or socket.gethostname()
        self.agent_id = _claims(token).get("sub")

    def _url(self, path: str) -> str:
        return f"{self.api_url}{path}"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "X-ThreatLens-SDK": SDK_VERSION}

    def _call_body(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        return {"session_id": self.session_id, "tool": tool, "args": args, "host": self.host, "pid": os.getpid()}

    def _content_body(self, source: str, text: str, carrier: str, raw: bytes | None,
                      media_type: str | None) -> dict[str, Any]:
        body: dict[str, Any] = {"session_id": self.session_id, "source": source, "carrier": carrier, "text": text}
        if raw is not None:
            body["content_b64"] = base64.b64encode(raw).decode()
            body["media_type"] = media_type
        return body

    def _needs_refresh(self) -> bool:
        c = _claims(self.token)
        # Delegated tokens can't be refreshed; the caller delegates again instead.
        return c.get("depth", 0) == 0 and c.get("exp", 0) - time.time() < REFRESH_MARGIN_S


class ThreatLensClient(_Base):
    """Synchronous client."""

    def __init__(self, api_url: str, token: str, *, session_id: str | None = None, host: str | None = None,
                 http: httpx.Client | None = None):
        super().__init__(api_url, token, session_id, host)
        self._http = http or httpx.Client(timeout=30)

    def call(self, tool: str, **args: Any) -> Any:
        """Run a tool through the gateway and return its result. Raises on any non-allow decision."""
        return self.call_raw(tool, args).get("result")

    def call_raw(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        self._refresh()
        r = self._http.post(self._url("/v1/gateway/tool-call"), json=self._call_body(tool, args),
                            headers=self._headers())
        return _raise_for(r)

    def register_content(self, source: str, text: str = "", carrier: str = "text", *,
                         raw: bytes | None = None, media_type: str | None = None) -> dict[str, Any]:
        """Report untrusted content the agent read (e.g. a document handed to it in its task).
        Pass the original bytes as `raw` for PDFs so hidden text can be found."""
        self._refresh()
        r = self._http.post(self._url("/v1/gateway/content"), headers=self._headers(),
                            json=self._content_body(source, text, carrier, raw, media_type))
        return _raise_for(r)

    def delegate(self, callee_id: str) -> "ThreatLensClient":
        """A client for another agent acting on this agent's behalf, with attenuated permissions."""
        self._refresh()
        r = self._http.post(self._url(f"/v1/agents/{self.agent_id}/delegate"), headers=self._headers(),
                            json={"callee_id": callee_id})
        token = _raise_for(r)["token"]
        return ThreatLensClient(self.api_url, token, session_id=self.session_id, host=self.host, http=self._http)

    def _refresh(self) -> None:
        if self._needs_refresh():
            r = self._http.post(self._url("/v1/agents/token/refresh"), headers=self._headers())
            self.token = _raise_for(r)["token"]


class AsyncThreatLensClient(_Base):
    """Async client (used by the in-process simulated agents)."""

    def __init__(self, api_url: str, token: str, *, session_id: str | None = None, host: str | None = None,
                 http: httpx.AsyncClient | None = None):
        super().__init__(api_url, token, session_id, host)
        self._http = http or httpx.AsyncClient(timeout=30)

    async def call(self, tool: str, **args: Any) -> Any:
        return (await self.call_raw(tool, args)).get("result")

    async def call_raw(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        await self._refresh()
        r = await self._http.post(self._url("/v1/gateway/tool-call"), json=self._call_body(tool, args),
                                  headers=self._headers())
        return _raise_for(r)

    async def register_content(self, source: str, text: str = "", carrier: str = "text", *,
                               raw: bytes | None = None, media_type: str | None = None) -> dict[str, Any]:
        await self._refresh()
        r = await self._http.post(self._url("/v1/gateway/content"), headers=self._headers(),
                                  json=self._content_body(source, text, carrier, raw, media_type))
        return _raise_for(r)

    async def delegate(self, callee_id: str) -> "AsyncThreatLensClient":
        await self._refresh()
        r = await self._http.post(self._url(f"/v1/agents/{self.agent_id}/delegate"), headers=self._headers(),
                                  json={"callee_id": callee_id})
        token = _raise_for(r)["token"]
        return AsyncThreatLensClient(self.api_url, token, session_id=self.session_id, host=self.host,
                                     http=self._http)

    async def _refresh(self) -> None:
        if self._needs_refresh():
            r = await self._http.post(self._url("/v1/agents/token/refresh"), headers=self._headers())
            self.token = _raise_for(r)["token"]
