"""M2 Gateway: Policy Enforcement Point for every agent tool call."""

from .catalog import BadToolArgs, Catalog, Label, ResolvedAction, ToolSpec, UnknownTool, in_scope
from .connector import HttpToolConnector, ToolError, ToolResult, UnconfiguredConnector
from .hooks import ActionScorer, ContentScanner, HashOnlyScanner, NullScorer, ScoreResult, ScoringContext
from .policy import TIER_ORDER, PolicyDecision, PolicyInput, decide, max_tier
from .service import Gateway, GatewayResult, ToolCallFailed, tier_for
from .session import SessionState, SessionStore
from .sinks import attach_mongo_sinks
from .tokens import issue_downstream, verify_downstream

__all__ = [
    "TIER_ORDER",
    "ActionScorer",
    "BadToolArgs",
    "Catalog",
    "ContentScanner",
    "Gateway",
    "GatewayResult",
    "HashOnlyScanner",
    "HttpToolConnector",
    "Label",
    "NullScorer",
    "PolicyDecision",
    "PolicyInput",
    "ResolvedAction",
    "ScoreResult",
    "ScoringContext",
    "SessionState",
    "SessionStore",
    "ToolCallFailed",
    "ToolError",
    "ToolResult",
    "ToolSpec",
    "UnconfiguredConnector",
    "UnknownTool",
    "attach_mongo_sinks",
    "decide",
    "in_scope",
    "issue_downstream",
    "max_tier",
    "tier_for",
    "verify_downstream",
]
