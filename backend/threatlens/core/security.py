"""Token and password primitives shared by agents, the gateway and analysts.

ponytail: HS256 with one shared key. Production swaps this for asymmetric keys
held in a KMS / the identity provider (PRODUCTION.md §2), same function shapes.
"""

from datetime import timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .config import Settings, get_settings
from .schemas import new_id, utcnow

ALGORITHM = "HS256"

# Token audiences: who is allowed to accept the token.
AUD_GATEWAY = "threatlens-gw"  # agent → gateway
AUD_TOOLS = "threatlens-tools"  # gateway → tool (per-call downstream token)
AUD_CONSOLE = "threatlens-console"  # analyst → console API

_hasher = PasswordHasher()


class InvalidToken(Exception):
    pass


def issue_token(
    subject: str,
    audience: str,
    ttl_s: int,
    claims: dict[str, Any] | None = None,
    settings: Settings | None = None,
) -> tuple[str, dict[str, Any]]:
    """Return (encoded token, payload). The payload includes a unique `jti`."""
    settings = settings or get_settings()
    now = utcnow()
    payload = {
        **(claims or {}),
        "sub": subject,
        "aud": audience,
        "iss": settings.jwt_issuer,
        "iat": now,
        "exp": now + timedelta(seconds=ttl_s),
        "jti": new_id("tok"),
    }
    return jwt.encode(payload, settings.jwt_signing_key, algorithm=ALGORITHM), payload


def verify_token(token: str, audience: str, settings: Settings | None = None) -> dict[str, Any]:
    """Check signature, expiry, issuer and audience. Revocation is checked by M1."""
    settings = settings or get_settings()
    try:
        return jwt.decode(
            token,
            settings.jwt_signing_key,
            algorithms=[ALGORITHM],
            audience=audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "jti", "sub", "aud", "iss"]},
        )
    except jwt.PyJWTError as e:
        raise InvalidToken(str(e)) from e


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
