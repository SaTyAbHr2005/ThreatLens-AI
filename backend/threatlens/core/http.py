"""Shared FastAPI dependencies used by every module's router."""

import hmac

from fastapi import Header, HTTPException, Request, status

from .config import Settings, get_settings
from .security import AUD_CONSOLE, InvalidToken, verify_token


def check_admin_key(settings: Settings, provided: str | None) -> None:
    """Operator access by API key (scripts, CI).

    prod: ADMIN_API_KEY must be configured and match.
    dev/test: open if no key is configured, otherwise it must match.
    """
    expected = settings.admin_api_key
    if not expected:
        if settings.env == "prod":
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "ADMIN_API_KEY is not configured")
        return
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing or invalid credentials")


def operator_principal(settings: Settings, admin_key: str | None, authorization: str | None) -> str:
    """Who is acting: an analyst's email (console JWT) or "operator" (API key / open dev mode)."""
    if authorization and authorization.lower().startswith("bearer "):
        try:
            return verify_token(authorization[7:].strip(), AUD_CONSOLE, settings)["sub"]
        except InvalidToken:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired session") from None
    check_admin_key(settings, admin_key)
    return "operator"


def require_operator(request: Request, x_admin_key: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)) -> str:
    request.state.principal = operator_principal(get_settings(), x_admin_key, authorization)
    return request.state.principal


def actor_for(request: Request, claimed: str) -> str:
    """An analyst acts as themself; the audit log can't be signed with someone else's name."""
    principal = getattr(request.state, "principal", "operator")
    return claimed if principal == "operator" else principal


def bearer_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    return authorization[7:].strip()


def registry(request: Request):
    return request.app.state.registry
