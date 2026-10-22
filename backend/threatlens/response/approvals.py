"""Step-up approvals: actions held for a person, executed only if approved.

ponytail: pending approvals live in memory, so they are dropped on restart (the
agent just retries). Persist them if approvals need to survive deploys.
"""

from datetime import timedelta
from typing import Any

from threatlens.core.schemas import ActionEvent, Approval, ApprovalStatus, utcnow
from threatlens.gateway import ResolvedAction, ToolCallFailed
from threatlens.identity import AgentToken

APPROVAL_TTL_S = 600


class ApprovalError(Exception):
    pass


class ApprovalQueue:
    def __init__(self, ttl_s: int = APPROVAL_TTL_S):
        self.ttl_s = ttl_s
        self._items: dict[str, Approval] = {}
        self._held: dict[str, tuple[AgentToken, dict[str, Any]]] = {}

    def hold(self, event: ActionEvent, claims: AgentToken, args: dict[str, Any], resolved: ResolvedAction,
             reason: str) -> Approval:
        a = Approval(
            expires_at=utcnow() + timedelta(seconds=self.ttl_s),
            agent_id=event.agent_id,
            session_id=event.session_id,
            event_id=event.id,
            tool=resolved.tool,
            resource=resolved.resource,
            sensitivity=resolved.label.sensitivity,
            destination=resolved.destination,
            reason=reason,
        )
        self._items[a.id] = a
        self._held[a.id] = (claims, dict(args))
        return a

    def get(self, approval_id: str) -> Approval | None:
        a = self._items.get(approval_id)
        if a and a.status is ApprovalStatus.pending and a.expires_at <= utcnow():
            a.status = ApprovalStatus.expired
            self._held.pop(a.id, None)
        return a

    def list(self, status: ApprovalStatus | None = None) -> list[Approval]:
        items = [self.get(i) for i in list(self._items)]
        return sorted((a for a in items if a and (status is None or a.status is status)),
                      key=lambda a: a.ts, reverse=True)

    async def decide(self, approval_id: str, approve: bool, actor: str, gateway) -> Approval:
        a = self.get(approval_id)
        if a is None:
            raise ApprovalError("no such approval")
        if a.status is not ApprovalStatus.pending:
            raise ApprovalError(f"already {a.status.value}")
        claims, args = self._held.pop(a.id)
        a.decided_by, a.decided_at = actor, utcnow()
        if not approve:
            a.status = ApprovalStatus.denied
            return a
        try:
            a.result = await gateway.execute_held(claims, a.session_id, a.tool, args, approved_by=actor)
            a.status = ApprovalStatus.approved
        except ToolCallFailed as e:
            a.status, a.result = ApprovalStatus.failed, {"error": str(e)}
        except PermissionError as e:  # the agent was isolated while the action waited
            a.status, a.result = ApprovalStatus.failed, {"error": str(e)}
        return a
