"""M2 Gateway: the Policy Enforcement Point every agent tool call passes through.

Lifecycle of one call (ARCHITECTURE.md §3):
  verify token → describe the action → score it → decide → (shadow?) →
  forward with a per-call downstream token → scan untrusted output → publish.
"""

import base64
import binascii
import logging
from typing import Any

from pydantic import BaseModel

from threatlens.core.bus import EventBus, Topics, bus as default_bus
from threatlens.core.config import Settings, get_settings
from threatlens.core.schemas import (
    Action,
    ActionEvent,
    Agent,
    AgentStatus,
    Carrier,
    ContentItem,
    DecisionType,
    DelegationContext,
    EnforcementMode,
    RuntimeFingerprint,
    Sensitivity,
    Tier,
    TrustLevel,
    new_id,
)
from threatlens.identity import Registry

from .catalog import BadToolArgs, Catalog, UnknownTool
from .connector import ToolError, UnconfiguredConnector
from .hooks import ActionScorer, ContentScanner, HashOnlyScanner, NullScorer, ScoreResult, ScoringContext
from .policy import PolicyDecision, PolicyInput, decide, max_tier
from .session import SessionStore
from .tokens import issue_downstream

log = logging.getLogger(__name__)

MAX_CONTENT_CHARS = 2_000_000


class GatewayResult(BaseModel):
    event_id: str
    decision: DecisionType
    tier: Tier
    rule: str
    reason: str
    shadow: bool = False
    would_be: DecisionType | None = None
    risk: float | None = None
    result: Any = None
    content_id: str | None = None  # set when the tool's output was registered as untrusted content


class ToolCallFailed(Exception):
    def __init__(self, event_id: str, error: ToolError):
        super().__init__(str(error))
        self.event_id = event_id
        self.status = error.status


def _b64(data: str | None) -> bytes | None:
    try:
        return base64.b64decode(data, validate=True) if data else None
    except (binascii.Error, ValueError):
        log.warning("tool returned invalid raw_b64; scanning its text only")
        return None


def tier_for(agent: Agent) -> Tier:
    return {
        AgentStatus.quarantined: Tier.isolate,
        AgentStatus.step_up: Tier.step_up,
        AgentStatus.restricted: Tier.restrict,
    }.get(agent.status, Tier.monitor if agent.drift >= 40 else Tier.allow)


class Gateway:
    def __init__(
        self,
        registry: Registry,
        catalog: Catalog,
        connector: Any = None,
        *,
        scorer: ActionScorer | None = None,
        scanner: ContentScanner | None = None,
        sessions: SessionStore | None = None,
        settings: Settings | None = None,
        bus: EventBus | None = None,
    ) -> None:
        self.registry = registry
        self.catalog = catalog
        self.connector = connector or UnconfiguredConnector()
        self.scorer = scorer or NullScorer()
        self.scanner = scanner or HashOnlyScanner()
        self.sessions = sessions or SessionStore()
        self.settings = settings or get_settings()
        self.bus = bus or default_bus

    async def tool_call(
        self, token: str, session_id: str, tool: str, args: dict[str, Any], runtime: RuntimeFingerprint
    ) -> GatewayResult:
        claims = self.registry.verify(token)  # InvalidToken / TokenRevoked / UnknownAgent propagate
        agent = self.registry.agent(claims.agent_id)
        contract = self.registry.contract(agent.role)
        session = self.sessions.get(agent.agent_id, session_id)

        event = ActionEvent(
            agent_id=agent.agent_id,
            role=agent.role,
            role_version=contract.version,
            session_id=session_id,
            token_jti=claims.jti,
            delegation=DelegationContext(
                parent=claims.chain[-2] if claims.depth else None, chain=claims.chain, depth=claims.depth
            ),
            runtime=runtime,
            action=Action(tool=tool),
            provenance=session.provenance(),
        )

        try:
            resolved = self.catalog.resolve(tool, args)
        except UnknownTool:
            # An attempt to use a tool nobody declared is itself worth recording.
            result = self._finish(event, session, Tier.allow, PolicyDecision(
                DecisionType.deny, "unknown_tool", f"{tool} is not a known tool."), shadow=False)
            self.bus.publish(Topics.action_scored, event)
            return result
        event.action = resolved.to_action(args)

        ctx = ScoringContext(claims=claims, agent=agent, contract=contract, session=session, action=resolved)
        score: ScoreResult | None
        try:
            score = await self.scorer.score(event, ctx)
        except Exception:
            log.exception("scorer failed for %s", event.id)
            score = None

        tier = max_tier(tier_for(agent), score.tier_floor if score else None)
        decision = decide(PolicyInput(
            tier=tier,
            claims=claims,
            contract=contract,
            chain_contracts=self._chain_contracts(claims.chain),
            grants=self.registry.grants(agent.agent_id),
            action=resolved,
            actions_last_minute=session.actions_last_minute(),
        ))

        sensitive = resolved.label.sensitivity.rank >= Sensitivity.confidential.rank
        if score is None and decision.allowed and sensitive and self.settings.fail_mode_sensitive == "closed":
            decision = PolicyDecision(
                DecisionType.deny, "fail_closed",
                "Detection is unavailable, so sensitive data is blocked until it recovers.")

        if score:
            event.scores, event.risk, event.alert_id = score.scores, score.risk, score.alert_id

        result = self._finish(
            event, session, tier, decision, shadow=contract.enforcement_mode is EnforcementMode.shadow
        )
        try:
            if result.decision in (DecisionType.allow, DecisionType.allow_logged):
                downstream = issue_downstream(claims, tool, resolved.resource, event.id, self.settings)
                try:
                    out = await self.connector.call(tool, args, downstream)
                except ToolError as e:
                    event.reason = f"Tool failed: {e}"
                    raise ToolCallFailed(event.id, e) from e
                event.action.bytes_in = out.bytes
                result.result = out.data
                if resolved.untrusted_output and (out.text or out.raw_b64):
                    raw = _b64(out.raw_b64)
                    item = await self._register(
                        session, resolved.resource, resolved.spec.carrier, out.text or "", raw, out.media_type
                    )
                    result.content_id = item.id
            return result
        finally:
            # Published once, after the tool ran, so subscribers see the complete event.
            self.bus.publish(Topics.action_scored, event)

    async def register_content(
        self, token: str, session_id: str, source: str, carrier: Carrier, text: str,
        raw: bytes | None = None, media_type: str | None = None,
    ) -> ContentItem:
        """An agent reports untrusted content it read outside a tool call (e.g. a file in its task)."""
        claims = self.registry.verify(token)
        if len(text) > MAX_CONTENT_CHARS or (raw is not None and len(raw) > MAX_CONTENT_CHARS):
            raise BadToolArgs(f"content is larger than {MAX_CONTENT_CHARS} characters")
        session = self.sessions.get(claims.agent_id, session_id)
        return await self._register(session, source, carrier, text, raw, media_type)

    # ------------------------------------------------------------ internals

    def _finish(self, event, session, tier, decision: PolicyDecision, *, shadow: bool) -> GatewayResult:
        effective = decision.decision
        if shadow and not decision.allowed:
            effective = DecisionType.allow_logged  # shadow mode: score and log, never block
        event.decision = effective
        event.shadow = shadow
        event.would_be = decision.decision if shadow else None
        event.rule, event.reason = decision.rule, decision.reason
        session.record(event)
        return GatewayResult(
            event_id=event.id,
            decision=effective,
            tier=tier,
            rule=decision.rule,
            reason=decision.reason,
            shadow=shadow,
            would_be=event.would_be,
            risk=event.risk,
        )

    async def _register(self, session, source: str, carrier: Carrier, text: str,
                        raw: bytes | None = None, media_type: str | None = None) -> ContentItem:
        try:
            item = await self.scanner.scan(source, carrier, text, TrustLevel.untrusted, raw, media_type)
        except Exception:
            # Unreadable content still counts as untrusted input: track it, unscored.
            log.exception("content scan failed for %s", source)
            item = await HashOnlyScanner().scan(source, carrier, text, TrustLevel.untrusted, raw, media_type)
        session.taint(item)
        self.bus.publish(Topics.content_scanned, item)
        return item

    def _chain_contracts(self, chain: list[str]):
        contracts = []
        for agent_id in chain:
            try:
                contracts.append(self.registry.contract(self.registry.agent(agent_id).role))
            except Exception:
                continue  # an agent removed mid-chain contributes no scope
        return contracts
