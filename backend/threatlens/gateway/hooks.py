"""Where later modules plug into the gateway.

- ActionScorer: M4 signals + M5 fusion score every action (may raise the tier).
- ContentScanner: M3 decodes and scores untrusted content.

Until those modules land, the defaults below keep the gateway fully working:
no scores, and content is hashed and tracked as taint but not yet scored.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Protocol

from threatlens.core.schemas import ActionEvent, Agent, Carrier, ContentItem, RoleContract, SignalId, Tier, TrustLevel
from threatlens.identity import AgentToken

from .catalog import ResolvedAction
from .session import SessionState


@dataclass
class ScoringContext:
    claims: AgentToken
    agent: Agent
    contract: RoleContract
    session: SessionState
    action: ResolvedAction


@dataclass
class ScoreResult:
    scores: dict[SignalId, float] = field(default_factory=dict)
    risk: float | None = None
    tier_floor: Tier | None = None  # raise this call's tier immediately (e.g. a tripwire)
    alert_id: str | None = None


class ActionScorer(Protocol):
    async def score(self, event: ActionEvent, ctx: ScoringContext) -> ScoreResult: ...


class ContentScanner(Protocol):
    async def scan(self, source: str, carrier: Carrier, text: str, trust: TrustLevel) -> ContentItem: ...


class NullScorer:
    async def score(self, event: ActionEvent, ctx: ScoringContext) -> ScoreResult:
        return ScoreResult()


class HashOnlyScanner:
    async def scan(self, source: str, carrier: Carrier, text: str, trust: TrustLevel) -> ContentItem:
        return ContentItem(
            source=source,
            carrier=carrier,
            trust_level=trust,
            sha256=hashlib.sha256(text.encode()).hexdigest(),
            scored_by="unscanned",
        )
