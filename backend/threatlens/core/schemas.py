"""The shared contract between all modules (and, via OpenAPI, the web app).

Rule: changes here are additive only. Never rename or remove a field once
another module depends on it.
"""

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


Score = float  # documented range [0, 1]


class _Model(BaseModel):
    model_config = ConfigDict(use_enum_values=False, populate_by_name=True)


# ---------------------------------------------------------------- enums


class Sensitivity(StrEnum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"

    @property
    def rank(self) -> int:
        return _SENSITIVITY_ORDER.index(self)


_SENSITIVITY_ORDER = list(Sensitivity)


class Tier(StrEnum):
    allow = "allow"
    monitor = "monitor"
    restrict = "restrict"
    step_up = "step_up"
    isolate = "isolate"


class DecisionType(StrEnum):
    allow = "allow"
    allow_logged = "allow_logged"
    deny = "deny"
    require_approval = "require_approval"
    quarantine = "quarantine"


class AgentStatus(StrEnum):
    active = "active"
    restricted = "restricted"
    step_up = "step_up"
    quarantined = "quarantined"


class EnforcementMode(StrEnum):
    enforce = "enforce"
    shadow = "shadow"


class TrustLevel(StrEnum):
    trusted = "trusted"  # produced inside the company by a known system
    internal = "internal"  # internal but user-generated
    untrusted = "untrusted"  # web, inbound email, external files, other agents


class SignalId(StrEnum):
    S0 = "S0"
    S1 = "S1"
    S2 = "S2"
    S3 = "S3"
    S4 = "S4"
    S5 = "S5"
    S6 = "S6"
    S7 = "S7"
    S8 = "S8"


SIGNAL_NAMES: dict[SignalId, str] = {
    SignalId.S0: "Runtime fingerprint",
    SignalId.S1: "Role conformance",
    SignalId.S2: "Sequence surprise",
    SignalId.S3: "Session anomaly",
    SignalId.S4: "Provenance taint",
    SignalId.S5: "Sensitivity & egress",
    SignalId.S6: "Delegation chain",
    SignalId.S7: "Slow drift",
    SignalId.S8: "Canary resource",
}


class AlertStatus(StrEnum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class AlertFeedback(StrEnum):
    mark_benign = "mark_benign"
    confirm_attack = "confirm_attack"
    approve_as_amendment = "approve_as_amendment"


Carrier = Literal["pdf", "email", "web", "tool_output", "agent_message", "text"]


# ---------------------------------------------------------------- role contracts


class RateEnvelope(_Model):
    actions_per_min: int = 30
    max_records_per_call: int = 500


class DelegationPolicy(_Model):
    may_call: list[str] = Field(default_factory=list)
    max_depth: int = 2


class RoleContract(_Model):
    """What an agent is *for*. Behavior is compared against this."""

    role: str
    version: int = 1
    purpose: str
    owner: str
    allowed_tools: list[str]
    # tool -> glob list (e.g. files.read) or constraint object (e.g. email.send recipients)
    resource_scopes: dict[str, Any] = Field(default_factory=dict)
    data_sensitivity_ceiling: Sensitivity = Sensitivity.internal
    egress_allowlist: list[str] = Field(default_factory=list)
    rate_envelope: RateEnvelope = Field(default_factory=RateEnvelope)
    prototype_actions: list[str] = Field(default_factory=list)
    delegation: DelegationPolicy = Field(default_factory=DelegationPolicy)
    enforcement_mode: EnforcementMode = EnforcementMode.enforce


class RoleAmendment(_Model):
    """A signed, human-approved legitimate change to a role."""

    id: str = Field(default_factory=lambda: new_id("amd"))
    role: str
    from_version: int
    to_version: int
    diff: dict[str, Any]
    reason: str
    signer: str
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None
    signature: str | None = None  # HMAC over the amendment; tampered amendments are ignored


class Agent(_Model):
    agent_id: str
    role: str
    role_version: int
    owner: str
    status: AgentStatus = AgentStatus.active
    drift: float = Field(0.0, ge=0, le=100)
    created_at: datetime = Field(default_factory=utcnow)
    # What the agent's credentials permit (IAM), as tool -> resource globs. Usually broader
    # than the Role Contract, as in real deployments. Empty = the contract's tools, any resource.
    grants: dict[str, list[str]] = Field(default_factory=dict)

    @property
    def trust(self) -> float:
        return round(100.0 - self.drift, 2)


# ---------------------------------------------------------------- actions


class RuntimeFingerprint(_Model):
    host: str | None = None
    ip: str | None = None
    sdk: str | None = None
    pid: int | None = None


class DelegationContext(_Model):
    parent: str | None = None
    chain: list[str] = Field(default_factory=list)
    depth: int = 0


class Action(_Model):
    tool: str
    resource: str | None = None
    resource_class: str | None = None
    sensitivity: Sensitivity = Sensitivity.internal
    args_digest: str | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    destination: str | None = None  # external host for egress actions


class Provenance(_Model):
    tainted_by: list[str] = Field(default_factory=list)  # ContentItem ids
    steps_since_taint: int | None = None


class ActionEvent(_Model):
    """One tool call, as seen by the gateway. Stored in `events`."""

    id: str = Field(default_factory=lambda: new_id("evt"))
    ts: datetime = Field(default_factory=utcnow)
    agent_id: str
    role: str
    role_version: int
    session_id: str
    token_jti: str
    delegation: DelegationContext = Field(default_factory=DelegationContext)
    runtime: RuntimeFingerprint = Field(default_factory=RuntimeFingerprint)
    action: Action
    provenance: Provenance = Field(default_factory=Provenance)
    scores: dict[SignalId, float] = Field(default_factory=dict)
    risk: float | None = Field(None, ge=0, le=100)
    decision: DecisionType | None = None
    shadow: bool = False  # scored in shadow mode: would-be decision, not enforced
    would_be: DecisionType | None = None  # shadow mode: what enforce mode would have done
    rule: str | None = None  # policy rule that produced the decision
    reason: str | None = None  # human-readable reason for the decision
    alert_id: str | None = None
    label: str | None = None  # ground truth, replay/eval mode only


# ---------------------------------------------------------------- content


class HiddenSpan(_Model):
    technique: str  # zero_width, unicode_tags, white_text, homoglyph, base64, ...
    start: int
    end: int
    text: str


class ContentItem(_Model):
    """Untrusted input an agent read. Becomes provenance taint."""

    id: str = Field(default_factory=lambda: new_id("cnt"))
    source: str  # file path, URL, message id
    carrier: Carrier
    trust_level: TrustLevel = TrustLevel.untrusted
    sha256: str
    injection_score: float = Field(0.0, ge=0, le=1)
    phishing_score: float | None = Field(None, ge=0, le=1)
    url_risk: float | None = Field(None, ge=0, le=1)
    techniques: list[str] = Field(default_factory=list)
    hidden_spans: list[HiddenSpan] = Field(default_factory=list)
    decoded_text: str = Field("", max_length=2000)
    scored_by: str = "heuristic"  # model | heuristic | llm | signature
    findings: list[str] = Field(default_factory=list)  # plain-language reasons behind the scores
    instruction: str = Field("", max_length=500)  # the most instruction-like sentence (attack fingerprint)
    read_by: str | None = None  # agent whose session read it (set by the gateway)
    signature_id: str | None = None  # matched a known attack in the fleet signature feed (M7)
    created_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------- detection & explanation


class SignalScore(_Model):
    signal: SignalId
    value: float = Field(ge=0, le=1)
    evidence: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class Factor(_Model):
    signal: SignalId
    contribution: float  # share of the logit, so factors are additive
    evidence: str


class Alert(_Model):
    id: str = Field(default_factory=lambda: new_id("alr"))
    ts: datetime = Field(default_factory=utcnow)
    agent_id: str
    session_id: str
    event_id: str
    risk: float = Field(ge=0, le=100)
    tier: Tier
    headline: str
    factors: list[Factor] = Field(default_factory=list)
    cause_content_id: str | None = None  # top-ranked cause (attribution accuracy metric)
    decoded_injection: str | None = None
    counterfactual: str | None = None
    timeline: list[str] = Field(default_factory=list)  # ActionEvent ids
    frameworks: list[str] = Field(default_factory=list)
    actions_taken: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.open
    feedback: AlertFeedback | None = None
    scores: dict[SignalId, float] = Field(default_factory=dict)  # all nine signals for the alerting action
    floor: str | None = None  # tripwire that set the risk floor (canary, sensitive_then_egress, ...)
    narrative: str | None = None  # plain-language summary written by an LLM from the structured fields
    narrative_source: str | None = None  # e.g. "llm:gemini"; None means the template headline is used
    updated_at: datetime = Field(default_factory=utcnow)
    action_count: int = 1  # alerting actions folded into this alert (one alert per agent session)
    containment: AgentStatus | None = None  # what was actually applied (M6); `tier` is only the risk band


class Decision(_Model):
    """Append-only audit record for every containment change."""

    id: str = Field(default_factory=lambda: new_id("dec"))
    ts: datetime = Field(default_factory=utcnow)
    agent_id: str
    decision: DecisionType
    tier: Tier
    reason: str
    actor: str = "system"  # "system" or an analyst id
    event_id: str | None = None
    alert_id: str | None = None
    from_status: AgentStatus | None = None
    to_status: AgentStatus | None = None
    details: dict[str, Any] = Field(default_factory=dict)  # e.g. revoked token count, flagged agents


class ApprovalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    denied = "denied"
    expired = "expired"
    failed = "failed"


class Approval(_Model):
    """A Step-up action held for a person to approve."""

    id: str = Field(default_factory=lambda: new_id("apr"))
    ts: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    agent_id: str
    session_id: str
    event_id: str
    tool: str
    resource: str | None = None
    sensitivity: Sensitivity
    destination: str | None = None
    reason: str
    status: ApprovalStatus = ApprovalStatus.pending
    decided_by: str | None = None
    decided_at: datetime | None = None
    result: Any = None  # the tool's result, once approved and run
