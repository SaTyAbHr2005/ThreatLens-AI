"""Downstream tokens: the only credential tools accept (bypass prevention, scenario A7).

For every allowed call the gateway mints a short-lived token bound to exactly
one tool and one resource, modelled on OAuth 2.0 Token Exchange (RFC 8693).
Agent tokens have a different audience, so a hijacked agent calling a tool
directly is refused.

ponytail: tools don't track jti, so a downstream token is replayable for its
60 s lifetime against the same tool+resource. Add a jti cache tool-side if needed.
"""

from typing import Any

from threatlens.core.config import Settings, get_settings
from threatlens.core.security import AUD_TOOLS, InvalidToken, issue_token, verify_token
from threatlens.identity import AgentToken


def issue_downstream(
    claims: AgentToken, tool: str, resource: str, event_id: str, settings: Settings | None = None
) -> str:
    settings = settings or get_settings()
    extra: dict[str, Any] = {"tool": tool, "resource": resource, "chain": claims.chain, "evt": event_id}
    if claims.act:
        extra["act"] = claims.act
    token, _ = issue_token(claims.agent_id, AUD_TOOLS, settings.downstream_token_ttl_s, extra, settings)
    return token


def verify_downstream(token: str, tool: str, resource: str, settings: Settings | None = None) -> dict[str, Any]:
    """Called by tool servers. Raises InvalidToken unless the token was minted for this exact call."""
    claims = verify_token(token, AUD_TOOLS, settings)
    if claims.get("tool") != tool or claims.get("resource") != resource:
        raise InvalidToken("token was minted for a different tool call")
    return claims
