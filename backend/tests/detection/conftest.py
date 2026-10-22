import os

import pytest

from threatlens.core.bus import EventBus, Topics
from threatlens.core.config import Settings
from threatlens.core.schemas import RuntimeFingerprint, SignalId
from threatlens.detection import CachedEmbedder, Detector, HashingEmbedder, make_embedder
from threatlens.gateway import Catalog, Gateway, ToolResult
from threatlens.identity import MemoryRegistryStore, Registry
from threatlens.scanner import ContentForensics

S = Settings(env="test", jwt_signing_key="detection-test-signing-key-0123456789-abc")

PROCUREMENT_GRANTS = {t: ["**"] for t in
                      ("supplier_db.query", "files.read", "erp.create_pr", "email.send", "web.fetch", "http.post")}


class OkTools:
    async def call(self, tool, args, token):
        return ToolResult(data={"ok": True}, bytes=100)

    async def aclose(self):
        pass


class D:
    """Gateway + Detector + real content scanner, with every published event captured."""

    def __init__(self, registry, gateway, detector, bus, events):
        self.registry, self.gateway, self.detector, self.bus, self.events = registry, gateway, detector, bus, events

    def token(self, agent_id: str) -> str:
        return self.registry.issue_token(agent_id).token

    async def call(self, who: str, tool: str, *, session: str = "s1", host: str = "worker-1", **args):
        token = who if "." in who else self.token(who)
        await self.gateway.tool_call(token, session, tool, args, RuntimeFingerprint(host=host, sdk="test"))
        await self.bus.drain()  # lets the detector learn before the next call
        return self.events[-1]

    @staticmethod
    def s(event, signal: str) -> float:
        return event.scores[SignalId(signal)]


@pytest.fixture
async def d(tmp_path_factory) -> D:
    registry = Registry(MemoryRegistryStore(), S)
    await registry.load()
    await registry.create_agent("procurement-agent", "procurement", "p@corp.example", PROCUREMENT_GRANTS)
    await registry.create_agent("finance-agent", "finance", "f@corp.example")
    await registry.create_agent("hr-agent", "hr", "h@corp.example")
    catalog = Catalog.load(S.catalog_dir)
    # RUN_MODEL_TESTS=1 runs every detection test against the real MiniLM model.
    embedder = (make_embedder("fastembed", S.embedding_model, tmp_path_factory.getbasetemp() / "models")
                if os.getenv("RUN_MODEL_TESTS") else CachedEmbedder(HashingEmbedder()))
    detector = Detector(registry, catalog, embedder)
    bus = EventBus()
    events: list = []

    async def capture(e):
        events.append(e)

    bus.subscribe(Topics.action_scored, capture)
    bus.subscribe(Topics.action_scored, detector.observe)
    gateway = Gateway(registry, catalog, OkTools(), scorer=detector, scanner=ContentForensics(), settings=S, bus=bus)
    yield D(registry, gateway, detector, bus, events)
    await bus.drain()
