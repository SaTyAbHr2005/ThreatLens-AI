import pytest

from threatlens.core.bus import EventBus, Topics
from threatlens.core.config import Settings
from threatlens.core.schemas import RuntimeFingerprint
from threatlens.detection import CachedEmbedder, Detector, HashingEmbedder
from threatlens.fusion import FusionScorer, MemoryAlertStore
from threatlens.gateway import Catalog, Gateway, ToolResult
from threatlens.identity import MemoryRegistryStore, Registry
from threatlens.intel import ImmuneScanner, IntelHub, SignatureBook
from threatlens.response import MemoryDecisionStore, ResponseOrchestrator
from threatlens.scanner import ContentForensics

S = Settings(env="test", jwt_signing_key="intel-test-signing-key-0123456789-abcdefgh")
GRANTS = {t: ["**"] for t in ("supplier_db.query", "files.read", "erp.create_pr", "email.send", "web.fetch", "http.post")}
from intel_data import HIDDEN, INSTRUCTION  # noqa: F401  (shared with the test modules)


class OkTools:
    async def call(self, tool, args, token):
        return ToolResult(data={"ok": True}, bytes=10)

    async def aclose(self):
        pass


class I:
    def __init__(self, registry, gateway, intel, response, bus):
        self.registry, self.gateway, self.intel, self.response, self.bus = registry, gateway, intel, response, bus

    def token(self, agent_id):
        return self.registry.issue_token(agent_id).token

    async def read(self, agent_id, source, text, session="s1"):
        item = await self.gateway.register_content(self.token(agent_id), session, source, "pdf", text)
        await self.bus.drain()
        return item

    async def call(self, agent_id, tool, session="s1", **args):
        res = await self.gateway.tool_call(self.token(agent_id), session, tool, args,
                                           RuntimeFingerprint(host="w1", sdk="t"))
        await self.bus.drain()
        return res


@pytest.fixture
async def i() -> I:
    registry = Registry(MemoryRegistryStore(), S)
    await registry.load()
    await registry.create_agent("procurement-agent", "procurement", "p@corp.example", GRANTS)
    await registry.create_agent("finance-agent", "finance", "f@corp.example")
    catalog = Catalog.load(S.catalog_dir)
    bus = EventBus()
    detector = Detector(registry, catalog, CachedEmbedder(HashingEmbedder()))
    fusion = FusionScorer(detector, registry, MemoryAlertStore())
    response = ResponseOrchestrator(fusion, registry, MemoryDecisionStore())
    book = SignatureBook()
    intel = IntelHub(registry, book)
    gateway = Gateway(registry, catalog, OkTools(), scorer=response,
                      scanner=ImmuneScanner(ContentForensics(), book), settings=S, bus=bus)
    gateway.approvals, response.gateway = response.approvals, gateway
    bus.subscribe(Topics.action_scored, detector.observe)
    fusion.attach(bus)
    response.attach(bus)
    intel.attach(bus)
    yield I(registry, gateway, intel, response, bus)
    await bus.drain()
