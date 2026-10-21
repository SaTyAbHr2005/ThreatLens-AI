import pytest

from threatlens.core.bus import EventBus, Topics
from threatlens.core.config import Settings
from threatlens.gateway import Catalog, Gateway
from threatlens.identity import MemoryRegistryStore, Registry

from gateway_fakes import PROCUREMENT_GRANTS, FakeTools

S = Settings(env="test", jwt_signing_key="gateway-test-signing-key-0123456789-abcdef")

class Harness:
    def __init__(self, registry: Registry, gateway: Gateway, tools: FakeTools, published: list):
        self.registry, self.gateway, self.tools, self.published = registry, gateway, tools, published

    def token(self, agent_id: str) -> str:
        return self.registry.issue_token(agent_id).token

    async def call(self, agent_id_or_token: str, tool: str, session: str = "s1", **args):
        token = self.token(agent_id_or_token) if "." not in agent_id_or_token else agent_id_or_token
        return await self.gateway.tool_call(token, session, tool, args, runtime=_runtime())


def _runtime():
    from threatlens.core.schemas import RuntimeFingerprint

    return RuntimeFingerprint(host="worker-1", ip="10.0.0.5", sdk="test")


@pytest.fixture
async def h() -> Harness:
    registry = Registry(MemoryRegistryStore(), S)
    await registry.load()
    await registry.create_agent("procurement-agent", "procurement", "p@corp.example", PROCUREMENT_GRANTS)
    await registry.create_agent("hr-agent", "hr", "h@corp.example")
    await registry.create_agent("finance-agent", "finance", "f@corp.example")
    await registry.create_agent("support-agent", "support", "s@corp.example")

    catalog = Catalog.load(S.catalog_dir)
    tools = FakeTools(catalog, S)
    bus = EventBus()
    published: list = []

    async def capture(event):
        published.append(event)

    bus.subscribe(Topics.action_scored, capture)
    gateway = Gateway(registry, catalog, tools, settings=S, bus=bus)
    harness = Harness(registry, gateway, tools, published)
    yield harness
    await bus.drain()
