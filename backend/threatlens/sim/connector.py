"""In-process ToolConnector for the mock enterprise (no HTTP hop; same checks as the HTTP route).

The gateway mints a downstream token per allowed call; this verifies it for the exact
tool and resource, exactly as a real tool server must, before running the handler.
"""

from typing import Any

from threatlens.core.config import Settings, get_settings
from threatlens.core.security import InvalidToken
from threatlens.gateway import ToolError, ToolResult
from threatlens.gateway.catalog import Catalog
from threatlens.gateway.tokens import verify_downstream

from .enterprise import HANDLERS, ExternalSink


class EnterpriseConnector:
    def __init__(self, catalog: Catalog, sink: ExternalSink, settings: Settings | None = None):
        self.catalog = catalog
        self.sink = sink
        self.settings = settings or get_settings()

    async def call(self, tool: str, args: dict[str, Any], token: str) -> ToolResult:
        resource = self.catalog.resolve(tool, args).resource
        try:
            verify_downstream(token, tool, resource, self.settings)
        except InvalidToken as e:
            raise ToolError(401, f"invalid downstream token: {e}") from e
        handler = HANDLERS.get(tool)
        if handler is None:
            raise ToolError(404, f"{tool} is not served by the mock enterprise")
        return handler(args, self.sink)

    async def aclose(self) -> None:
        pass
