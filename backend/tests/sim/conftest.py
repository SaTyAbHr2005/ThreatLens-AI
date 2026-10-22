import pytest

from threatlens.core.bus import EventBus, Topics
from threatlens.core.config import Settings
from threatlens.detection import CachedEmbedder, Detector, HashingEmbedder
from threatlens.fusion import FusionScorer, MemoryAlertStore
from threatlens.gateway import Catalog, Gateway
from threatlens.identity import MemoryRegistryStore, Registry
from threatlens.intel import ImmuneScanner, IntelHub, SignatureBook
from threatlens.response import MemoryDecisionStore, ResponseOrchestrator
from threatlens.scanner import ContentForensics
from threatlens.sim import EnterpriseConnector, ExternalSink, ScenarioRunner

S = Settings(env="test", jwt_signing_key="sim-scenario-test-key-0123456789-abcdefgh")


@pytest.fixture
async def runner(request) -> ScenarioRunner:
    """Full stack behind a ScenarioRunner. Pass param=llm_router to supply an arena-style LLM."""
    registry = Registry(MemoryRegistryStore(), S)
    await registry.load()
    catalog = Catalog.load(S.catalog_dir)
    bus = EventBus()
    detector = Detector(registry, catalog, CachedEmbedder(HashingEmbedder()))
    fusion = FusionScorer(detector, registry, MemoryAlertStore())
    response = ResponseOrchestrator(fusion, registry, MemoryDecisionStore())
    sink = ExternalSink()
    gateway = Gateway(registry, catalog, EnterpriseConnector(catalog, sink, S), scorer=response,
                      scanner=ImmuneScanner(ContentForensics(), SignatureBook()), settings=S, bus=bus)
    gateway.approvals, response.gateway = response.approvals, gateway
    bus.subscribe(Topics.action_scored, detector.observe)
    fusion.attach(bus)
    response.attach(bus)
    IntelHub(registry, SignatureBook()).attach(bus)
    llm = getattr(request, "param", None)
    yield ScenarioRunner(registry, gateway, fusion, sink, llm)
    await bus.drain()
