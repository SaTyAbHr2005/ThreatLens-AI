"""Shared FastAPI dependencies used by every module's router."""

import hmac

from fastapi import Header, HTTPException, Request, status

from .config import Settings, get_settings


def check_admin_key(settings: Settings, provided: str | None) -> None:
    """Operator access until analyst login (M10).

    prod: ADMIN_API_KEY must be configured and match.
    dev/test: open if no key is configured, otherwise it must match.
    """
    expected = settings.admin_api_key
    if not expected:
        if settings.env == "prod":
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "ADMIN_API_KEY is not configured")
        return
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing or invalid X-Admin-Key")


def require_operator(x_admin_key: str | None = Header(default=None)) -> None:
    check_admin_key(get_settings(), x_admin_key)


def bearer_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    return authorization[7:].strip()


def registry(request: Request):
    return request.app.state.registry
