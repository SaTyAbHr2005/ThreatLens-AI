from typing import Any


class ThreatLensError(Exception):
    """Base error. `response` holds the gateway's JSON body when there is one."""

    def __init__(self, message: str, *, status: int | None = None, response: dict[str, Any] | None = None):
        super().__init__(message)
        self.status = status
        self.response = response or {}
        self.event_id: str | None = self.response.get("event_id")
        self.reason: str | None = self.response.get("reason")


class AuthError(ThreatLensError):
    """The token was rejected (expired, revoked, or for another agent)."""


class ActionDenied(ThreatLensError):
    """The gateway blocked this call. The agent can carry on with other work."""


class ApprovalRequired(ThreatLensError):
    """The call is held for a person to approve (Step-up tier)."""


class AgentQuarantined(ThreatLensError):
    """The agent is isolated. Stop working and wait for an analyst."""


class ToolFailed(ThreatLensError):
    """The call was allowed but the tool itself failed."""
