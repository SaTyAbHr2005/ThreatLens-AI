"""ToolConnector adapter: how allowed calls reach the real tools.

Hackathon: the mock enterprise over HTTP. Production: MCP servers / SaaS APIs
behind the same `call` method (PRODUCTION.md §2).
"""

from typing import Any

import httpx
from pydantic import BaseModel


class ToolResult(BaseModel):
    data: Any = None
    text: str | None = None  # readable content, scanned when the tool's output is untrusted
    bytes: int = 0


class ToolError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class HttpToolConnector:
    """POST {base_url}/tools/{tool} with the downstream token as the bearer."""

    def __init__(self, base_url: str, *, transport: httpx.AsyncBaseTransport | None = None, timeout_s: float = 20):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(transport=transport, timeout=timeout_s)

    async def call(self, tool: str, args: dict[str, Any], token: str) -> ToolResult:
        try:
            r = await self._client.post(
                f"{self.base_url}/tools/{tool}", json=args, headers={"Authorization": f"Bearer {token}"}
            )
        except httpx.HTTPError as e:
            raise ToolError(502, f"tool backend unreachable: {type(e).__name__}") from e
        if r.status_code >= 400:
            raise ToolError(r.status_code, f"tool returned HTTP {r.status_code}")
        result = ToolResult.model_validate(r.json())
        result.bytes = result.bytes or len(r.content)
        return result

    async def aclose(self) -> None:
        await self._client.aclose()


class UnconfiguredConnector:
    async def call(self, tool: str, args: dict[str, Any], token: str) -> ToolResult:
        raise ToolError(503, "no tool backend configured (set TOOLS_BASE_URL)")

    async def aclose(self) -> None:
        pass
