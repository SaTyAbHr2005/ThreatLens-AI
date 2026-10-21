"""Policy Decision Point: one tool call + the agent's current tier → a decision.

Rules, in order:
  1. Isolated agent                                   → quarantine
  2. Tool outside the token's scope (incl. delegation) → deny     ┐ what IAM checks
  3. Resource outside the agent's grants               → deny     ┘
  4. Tool outside the Role Contract                    → deny
  5. Rate above the role envelope (2× normally, 1× when contained) → deny
  At Restrict / Step-up, the agent snaps back to its Role Contract:
  6. Resource outside the contract scope of any agent in the chain → deny
  7. Data above the role's sensitivity ceiling          → deny
  8. Egress to a host outside the role's allowlist      → deny
  9. Step-up: sensitive data or external egress         → require approval

At Allow / Monitor only rules 1–5 apply, so a hijacked agent reading data its
credentials permit is *allowed* here and must be caught by detection (M4/M5).
That is the problem statement: valid credentials hide the attack.
"""

from dataclasses import dataclass

from threatlens.core.schemas import DecisionType, RoleContract, Sensitivity, Tier
from threatlens.identity import AgentToken

from .catalog import ResolvedAction, in_scope

TIER_ORDER = [Tier.allow, Tier.monitor, Tier.restrict, Tier.step_up, Tier.isolate]


def max_tier(*tiers: Tier | None) -> Tier:
    return max((t for t in tiers if t is not None), key=TIER_ORDER.index, default=Tier.allow)


@dataclass(frozen=True)
class PolicyInput:
    tier: Tier
    claims: AgentToken
    contract: RoleContract  # the acting agent's contract
    chain_contracts: list[RoleContract]  # contracts of every agent in the delegation chain
    grants: dict[str, list[str]]  # the acting agent's credential permissions
    action: ResolvedAction
    actions_last_minute: int


@dataclass(frozen=True)
class PolicyDecision:
    decision: DecisionType
    rule: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision in (DecisionType.allow, DecisionType.allow_logged)


def _deny(rule: str, reason: str) -> PolicyDecision:
    return PolicyDecision(DecisionType.deny, rule, reason)


def decide(p: PolicyInput) -> PolicyDecision:
    a, c, tool = p.action, p.contract, p.action.tool
    contained = p.tier in (Tier.restrict, Tier.step_up)

    if p.tier is Tier.isolate:
        return PolicyDecision(DecisionType.quarantine, "isolated", "This agent is isolated pending review.")
    if tool not in p.claims.scopes:
        return _deny("token_scope", f"{tool} is not in this token's scope.")
    grant = p.grants.get(tool)
    if grant is None or not in_scope(a.spec.kind, a.resource, grant):
        return _deny("grant", f"{a.resource} is outside what this agent's credentials permit for {tool}.")
    if tool not in c.allowed_tools:
        return _deny("contract_tool", f"{tool} is not part of the {c.role} role.")

    envelope = c.rate_envelope.actions_per_min
    if p.actions_last_minute >= (envelope if contained or p.tier is Tier.monitor else envelope * 2):
        return _deny("rate", f"More than {envelope} actions a minute is outside the {c.role} role's envelope.")

    if contained:
        for rc in p.chain_contracts:
            scope = rc.resource_scopes.get(tool)
            if scope is not None and not in_scope(a.spec.kind, a.resource, scope):
                return _deny("contract_scope", f"{a.resource} is outside the {rc.role} role's scope for {tool}.")
        if a.label.sensitivity.rank > c.data_sensitivity_ceiling.rank:
            return _deny(
                "ceiling",
                f"{a.label.sensitivity.value} data is above the {c.role} role's "
                f"{c.data_sensitivity_ceiling.value} ceiling.",
            )
        egress_out = a.spec.egress and a.external
        if egress_out and a.spec.kind == "url" and a.destination not in c.egress_allowlist:
            return _deny("egress", f"Sending data to {a.destination} isn't in the {c.role} role's allowlist.")
        if p.tier is Tier.step_up and (a.label.sensitivity.rank >= Sensitivity.confidential.rank or egress_out):
            return PolicyDecision(
                DecisionType.require_approval, "step_up", "Held for a person to approve while this agent is under review."
            )

    if p.tier is Tier.allow:
        return PolicyDecision(DecisionType.allow, "ok", "Allowed.")
    return PolicyDecision(DecisionType.allow_logged, "ok", f"Allowed with full logging ({p.tier.value}).")
