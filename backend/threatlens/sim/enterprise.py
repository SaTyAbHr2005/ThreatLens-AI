"""Mock enterprise: the tools the gateway forwards allowed calls to.

Every handler verifies the gateway's per-call downstream token for the exact tool
and resource, so a token minted for another call, or an agent token used directly,
is refused (scenario A7). All data is synthetic (`data.py`). The external sink
records exfiltration attempts and never touches the network.

In production these handlers are real MCP servers / SaaS APIs behind the same
`POST /tools/{tool}` shape (PRODUCTION.md §2).
"""

import base64
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from threatlens.core.config import Settings, get_settings
from threatlens.core.security import InvalidToken
from threatlens.gateway import ToolResult
from threatlens.gateway.catalog import Catalog
from threatlens.gateway.tokens import verify_downstream

from . import data

router = APIRouter(prefix="/enterprise", tags=["mock-enterprise"])


class Egress(BaseModel):
    """Recorded exfiltration attempts: where, how many bytes. Nothing is actually sent."""

    destination: str
    bytes: int
    preview: str


class ExternalSink:
    def __init__(self) -> None:
        self.received: list[Egress] = []

    def record(self, destination: str, body: str) -> None:
        self.received.append(Egress(destination=destination, bytes=len(body), preview=body[:200]))

    @property
    def total_bytes(self) -> int:
        return sum(e.bytes for e in self.received)


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "tools require the gateway's downstream token")
    return authorization[7:].strip()


def catalog(request: Request) -> Catalog:
    return request.app.state.gateway.catalog


def sink(request: Request) -> ExternalSink:
    return request.app.state.external_sink


HANDLERS = {}


def tool(name: str):
    def register(fn):
        HANDLERS[name] = fn
        return fn
    return register


@router.post("/tools/{tool_name}", response_model=ToolResult)
async def run_tool(tool_name: str, request: Request, authorization: str | None = Header(default=None)):
    args: dict[str, Any] = await request.json()
    cat, settings = catalog(request), get_settings()
    try:
        resource = cat.resolve(tool_name, args).resource
    except Exception as e:
        raise HTTPException(400, f"bad tool call: {e}") from e
    try:
        verify_downstream(_bearer(authorization), tool_name, resource, settings)  # A7: wrong/agent token → 401
    except InvalidToken as e:
        raise HTTPException(401, f"invalid downstream token: {e}") from e
    handler = HANDLERS.get(tool_name)
    if handler is None:
        raise HTTPException(404, f"{tool_name} is not served here")
    return handler(args, sink(request))


def _pdf_result(resource: str, content: bytes) -> ToolResult:
    return ToolResult(data={"path": resource, "type": "pdf"},
                      raw_b64=base64.b64encode(content).decode(), media_type="application/pdf", bytes=len(content))


@tool("files.read")
def _files_read(args, sink) -> ToolResult:
    path = args["path"]
    content = data.FILES.get(path)
    if content is None:
        return ToolResult(data={"path": path, "error": "not found"}, text="", bytes=0)
    if isinstance(content, bytes):
        return _pdf_result(path, content)
    # Inbox files are untrusted; other files are trusted (the catalog decides what gets scanned).
    return ToolResult(data={"path": path}, text=content, bytes=len(content))


@tool("supplier_db.query")
def _supplier(args, sink) -> ToolResult:
    rows = data.SUPPLIERS.get(args.get("table", "prices"), [])
    return ToolResult(data=rows, bytes=len(str(rows)))


@tool("erp.create_pr")
def _create_pr(args, sink) -> ToolResult:
    return ToolResult(data={"pr_id": "PR-1003", "supplier": args.get("supplier"),
                            "item": args.get("item"), "qty": args.get("qty"), "status": "created"})


@tool("erp.read_invoice")
def _invoice(args, sink) -> ToolResult:
    inv = data.INVOICES.get(args.get("invoice_id", ""))
    return ToolResult(data=inv or {"error": "not found"}, bytes=len(str(inv)))


@tool("erp.read_pr")
def _read_pr(args, sink) -> ToolResult:
    return ToolResult(data={"pr_id": args.get("pr_id"), "status": "approved"})


@tool("ledger.query")
def _ledger(args, sink) -> ToolResult:
    rows = data.LEDGERS.get(args.get("ledger", "payables"), [])
    return ToolResult(data=rows, bytes=len(str(rows)))


@tool("hr_db.query")
def _hr_query(args, sink) -> ToolResult:
    rows = data.EMPLOYEES.get(args.get("table", "profile"), [])
    text = str(rows) if args.get("table") == "compensation" else None  # salary data is scannable content
    return ToolResult(data=rows, text=text, bytes=len(str(rows)))


@tool("hr_db.update")
def _hr_update(args, sink) -> ToolResult:
    return ToolResult(data={"table": args.get("table"), "status": "updated"})


@tool("tickets.read")
def _ticket(args, sink) -> ToolResult:
    body = data.TICKETS.get(args.get("ticket_id", ""), "")
    return ToolResult(data={"ticket_id": args.get("ticket_id")}, text=body, bytes=len(body))


@tool("tickets.update")
def _ticket_update(args, sink) -> ToolResult:
    return ToolResult(data={"ticket_id": args.get("ticket_id"), "status": "updated"})


@tool("kb.search")
def _kb(args, sink) -> ToolResult:
    return ToolResult(data=data.KB, bytes=len(str(data.KB)))


@tool("logistics_api.track")
def _track(args, sink) -> ToolResult:
    return ToolResult(data={"shipment_id": args.get("shipment_id"),
                            "status": data.SHIPMENTS.get(args.get("shipment_id", ""), "unknown")})


@tool("web.fetch")
def _web(args, sink) -> ToolResult:
    from urllib.parse import urlsplit

    host = (urlsplit(args.get("url", "")).hostname or "").lower()
    body = data.SUPPLIER_PORTAL.get(host, f"(page at {host})")
    return ToolResult(data={"url": args.get("url")}, text=body, bytes=len(body))


@tool("email.send")
def _email(args, sink: ExternalSink) -> ToolResult:
    to = args.get("to", "")
    body = str(args.get("body", ""))
    domain = to.rpartition("@")[2].lower()
    if domain and not (domain == "corp.example" or domain.endswith(".corp.example")):  # leaving the company
        sink.record(domain, body)
    return ToolResult(data={"to": to, "status": "sent"})


@tool("http.post")
def _http_post(args, sink: ExternalSink) -> ToolResult:
    from urllib.parse import urlsplit

    host = (urlsplit(args.get("url", "")).hostname or "unknown").lower()
    sink.record(host, str(args.get("body", "")))  # recorded, never actually sent
    return ToolResult(data={"url": args.get("url"), "status": "200 OK"})


@tool("payments.transfer")
def _transfer(args, sink: ExternalSink) -> ToolResult:
    sink.record(f"payment:{args.get('to_account')}", str(args.get("amount", "")))
    return ToolResult(data={"to_account": args.get("to_account"), "status": "submitted"})
