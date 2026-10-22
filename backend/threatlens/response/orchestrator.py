"""M6 Response Orchestrator: turns risk into containment, and analyst decisions into action.

Plugs into the gateway as its ActionScorer (wrapping M5), so containment is decided on
the same call that triggered it: the risky action itself is judged under the new tier.
"""

import logging
from typing import Any

from threatlens.core.bus import EventBus, Topics
from threatlens.core.schemas import (
    ActionEvent,
    Agent,
    AgentStatus,
    Alert,
    AlertFeedback,
    AlertStatus,
    Decision,
    DecisionType,
    EnforcementMode,
    RoleAmendment,
    Tier,
)
from threatlens.gateway.catalog import in_scope
from threatlens.gateway.hooks import ScoreResult, ScoringContext
from threatlens.identity import Registry, UnknownAgent

from .approvals import ApprovalQueue
from .policy import escalation, is_strike, level, relaxation

log = logging.getLogger(__name__)

TIER_FOR = {
    AgentStatus.active: Tier.allow,
    AgentStatus.restricted: Tier.restrict,
    AgentStatus.step_up: Tier.step_up,
    AgentStatus.quarantined: Tier.isolate,
}
DECISION_FOR = {
    AgentStatus.active: DecisionType.allow,
    AgentStatus.restricted: DecisionType.deny,
    AgentStatus.step_up: DecisionType.require_approval,
    AgentStatus.quarantined: DecisionType.quarantine,
}
ACTION_TEXT = {
    AgentStatus.restricted: "Restricted: access cut back to the Role Contract (in-role work continues)",
    AgentStatus.step_up: "Step-up: scope cut back to the Role Contract; sensitive data and external sends need approval",
    AgentStatus.quarantined: "Isolated: agent paused and its tokens revoked",
    AgentStatus.active: "Released: normal access restored",
}
CHILD_DRIFT_FLOOR = 40.0


class NothingToAmend(ValueError):
    pass


class ResponseOrchestrator:
    def __init__(self, fusion, registry: Registry, decisions, *, approvals: ApprovalQueue | None = None,
                 bus: EventBus | None = None):
        self.fusion = fusion
        self.registry = registry
        self.decisions = decisions
        self.approvals = approvals or ApprovalQueue()
        self.bus = bus
        self.gateway = None  # set after the gateway is built (for held calls and event lookups)
        self._strikes: dict[str, int] = {}
        self._streak: dict[str, int] = {}

    # ------------------------------------------------------------ hot path

    async def score(self, event: ActionEvent, ctx: ScoringContext) -> ScoreResult:
        before = ctx.agent.status
        r = await self.fusion.score(event, ctx)
        risk = r.risk or 0.0
        agent_id = ctx.agent.agent_id
        if is_strike(before, risk):
            self._strikes[agent_id] = self._strikes.get(agent_id, 0) + 1
        strikes = self._strikes.get(agent_id, 0)
        target = escalation(before, risk, ctx.agent.drift, r.tripwires, strikes)
        # Shadow mode scores and alerts but never contains (the alert still says what would happen).
        if level(target) > level(before) and ctx.contract.enforcement_mode is not EnforcementMode.shadow:
            await self._set_status(ctx.agent, target, self._why(target, r, event, strikes), "system",
                                   event=event, alert_id=r.alert_id)
        alert = self.fusion.live_alert(r.alert_id) if r.alert_id else None
        if alert is not None and alert.containment is not ctx.agent.status:
            alert.containment = ctx.agent.status  # what was actually applied, not just the risk band
            await self.fusion.save_alert(alert)
        r.tier_floor = TIER_FOR[ctx.agent.status]
        return r

    @staticmethod
    def _why(target: AgentStatus, r: ScoreResult, event: ActionEvent, strikes: int) -> str:
        what = f"{event.action.tool} {event.action.resource or ''}".strip()
        if target is AgentStatus.quarantined:
            if "canary" in r.tripwires:
                return f"Touched a canary resource ({what})."
            if "token_in_two_places" in r.tripwires:
                return "The same token is in use from two machines (likely stolen)."
            return f"{strikes} high-risk actions while already contained (latest: {what}, risk {r.risk:.0f})."
        return f"Risk {r.risk:.0f} on {what}."

    # ------------------------------------------------------------ status changes (all of them go through here)

    async def _set_status(self, agent: Agent, target: AgentStatus, reason: str, actor: str, *,
                          event: ActionEvent | None = None, alert_id: str | None = None,
                          drift: float | None = None) -> Decision:
        before = agent.status
        await self.registry.set_status(agent.agent_id, target, drift)
        details: dict[str, Any] = {}
        if target is AgentStatus.quarantined:
            downstream = self.registry.downstream_agents(agent.agent_id)
            revoked = await self.registry.revoke_agent(agent.agent_id)
            for child in sorted(downstream):
                self.fusion.drift.bump(child, CHILD_DRIFT_FLOOR)
                try:
                    c = self.registry.agent(child)
                    c.drift = max(c.drift, CHILD_DRIFT_FLOOR)
                except UnknownAgent:
                    pass
            for a in self.approvals.list():
                if a.agent_id == agent.agent_id and a.status.value == "pending":
                    await self.approvals.decide(a.id, False, "system", self.gateway)
            details = {"revoked_tokens": len(revoked), "flagged_agents": sorted(downstream)}
        self._streak[agent.agent_id] = 0
        if target is AgentStatus.active:
            self._strikes[agent.agent_id] = 0

        decision = Decision(
            agent_id=agent.agent_id, decision=DECISION_FOR[target], tier=TIER_FOR[target], reason=reason,
            actor=actor, event_id=event.id if event else None, alert_id=alert_id,
            from_status=before, to_status=target, details=details,
        )
        await self.decisions.add(decision)

        alert = self._alert_for(agent.agent_id, event, alert_id)
        if alert is not None:
            alert.containment = target
            text = ACTION_TEXT[target]
            if details.get("revoked_tokens"):
                text += f" ({details['revoked_tokens']} token(s) revoked"
                text += f"; acting-for agents flagged: {', '.join(details['flagged_agents'])})" if details[
                    "flagged_agents"] else ")"
            alert.actions_taken.append(text + f" [{actor}]")
            await self.fusion.save_alert(alert)
        if self.bus:
            self.bus.publish(Topics.containment_changed, decision)
        return decision

    def _alert_for(self, agent_id: str, event: ActionEvent | None, alert_id: str | None) -> Alert | None:
        if alert_id:
            return self.fusion.live_alert(alert_id)
        if event:
            return self.fusion.open_alert(agent_id, event.session_id)
        return None

    # ------------------------------------------------------------ off the hot path

    def attach(self, bus: EventBus):
        self.bus = bus
        return [bus.subscribe(Topics.action_scored, self._on_action)]

    async def _on_action(self, event: ActionEvent) -> None:
        try:
            agent = self.registry.agent(event.agent_id)
        except UnknownAgent:
            return
        # 1. Note what was stopped on the alert's record of actions taken.
        if event.alert_id and event.decision in (DecisionType.deny, DecisionType.quarantine,
                                                 DecisionType.require_approval):
            alert = self.fusion.live_alert(event.alert_id)
            if alert is not None:
                verb = "Held for approval" if event.decision is DecisionType.require_approval else "Blocked"
                note = f"{verb}: {event.action.tool} {event.action.resource or ''}".strip() + f" ({event.rule})"
                if note not in alert.actions_taken:
                    alert.actions_taken.append(note)
                    await self.fusion.save_alert(alert)
        # 2. Relax containment after a streak of clean actions (never out of isolation).
        clean = (event.risk or 0) < 40 and event.decision in (DecisionType.allow, DecisionType.allow_logged)
        self._streak[agent.agent_id] = self._streak.get(agent.agent_id, 0) + 1 if clean else 0
        target = relaxation(agent.status, agent.drift, self._streak[agent.agent_id])
        if target is not agent.status:
            await self._set_status(agent, target, f"{self._streak[agent.agent_id]} clean actions in a row.",
                                   "system", event=event)

    # ------------------------------------------------------------ analyst actions

    async def apply(self, agent_id: str, action: str, reason: str, actor: str) -> Decision:
        agent = self.registry.agent(agent_id)
        target = {"release": AgentStatus.active, "restrict": AgentStatus.restricted,
                  "step_up": AgentStatus.step_up, "isolate": AgentStatus.quarantined}[action]
        if action == "release":
            self.fusion.reset_agent(agent_id)
            return await self._set_status(agent, target, reason, actor, drift=0.0)
        return await self._set_status(agent, target, reason, actor)

    async def feedback(self, alert_id: str, feedback: AlertFeedback, actor: str, reason: str) -> dict[str, Any]:
        alert = self.fusion.live_alert(alert_id) or await self.fusion.alerts.get(alert_id)
        if alert is None:
            raise KeyError(alert_id)
        out: dict[str, Any] = {}
        if feedback is AlertFeedback.approve_as_amendment:
            out["amendment"] = await self._amend_from(alert, actor, reason)
        alert.feedback = feedback
        alert.status = AlertStatus.acknowledged if feedback is AlertFeedback.confirm_attack else AlertStatus.resolved
        alert.actions_taken.append(f"Analyst feedback: {feedback.value.replace('_', ' ')} [{actor}]")
        await self.fusion.save_alert(alert)
        if feedback is not AlertFeedback.confirm_attack:
            out["decision"] = await self.apply(alert.agent_id, "release", f"{feedback.value}: {reason}", actor)
        out["alert"] = alert
        return out

    async def _amend_from(self, alert: Alert, actor: str, reason: str) -> RoleAmendment:
        event = self._event(alert.agent_id, alert.event_id)
        if event is None:
            raise NothingToAmend("the alerting action is no longer in memory; amend the role directly")
        agent = self.registry.agent(alert.agent_id)
        changes = amendment_for(event, self.registry.contract(agent.role), self.gateway.catalog)
        return await self.registry.amend(agent.role, changes, reason or f"Approved from alert {alert.id}", actor)

    def _event(self, agent_id: str, event_id: str) -> ActionEvent | None:
        if self.gateway is None:
            return None
        for s in self.gateway.sessions.for_agent(agent_id):
            for e in s.history:
                if e.id == event_id:
                    return e
        return None


def amendment_for(event: ActionEvent, contract, catalog) -> dict[str, Any]:
    """The smallest Role Contract change that would make this action in-role."""
    a = event.action
    spec = catalog.tools.get(a.tool)
    changes: dict[str, Any] = {}
    if a.tool not in contract.allowed_tools:
        changes["allowed_tools"] = {"add": [a.tool]}
    scope = contract.resource_scopes.get(a.tool)
    kind = spec.kind if spec else "name"
    if scope is not None and a.resource and not in_scope(kind, a.resource, scope):
        if isinstance(scope, dict):
            changes["resource_scopes"] = {a.tool: {**scope, "recipients": [*scope.get("recipients", []), a.resource]}}
        else:
            changes["resource_scopes"] = {a.tool: [*scope, a.destination if kind == "url" else a.resource]}
    if a.sensitivity.rank > contract.data_sensitivity_ceiling.rank:
        changes["data_sensitivity_ceiling"] = a.sensitivity.value
    if spec and spec.egress and kind == "url" and a.destination and a.destination not in contract.egress_allowlist:
        changes["egress_allowlist"] = {"add": [a.destination]}
    if not changes:
        raise NothingToAmend("this action is already within the role")
    return changes
