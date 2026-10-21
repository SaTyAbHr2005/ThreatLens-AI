import pytest

from threatlens.core.config import Settings
from threatlens.core.security import (
    AUD_GATEWAY,
    AUD_TOOLS,
    InvalidToken,
    hash_password,
    issue_token,
    verify_password,
    verify_token,
)

S = Settings(env="test", jwt_signing_key="test-key-0123456789-0123456789-ab")


def test_token_roundtrip_carries_claims_and_jti():
    token, payload = issue_token("procurement-agent", AUD_GATEWAY, 60, {"role": "procurement"}, S)
    claims = verify_token(token, AUD_GATEWAY, S)
    assert claims["sub"] == "procurement-agent"
    assert claims["role"] == "procurement"
    assert claims["jti"] == payload["jti"] and claims["jti"].startswith("tok_")


def test_agent_token_is_rejected_by_tools():
    """Bypass prevention: a token minted for the gateway must not work on tools."""
    token, _ = issue_token("procurement-agent", AUD_GATEWAY, 60, settings=S)
    with pytest.raises(InvalidToken):
        verify_token(token, AUD_TOOLS, S)


def test_expired_and_tampered_tokens_fail():
    expired, _ = issue_token("a", AUD_GATEWAY, -1, settings=S)
    with pytest.raises(InvalidToken):
        verify_token(expired, AUD_GATEWAY, S)

    good, _ = issue_token("a", AUD_GATEWAY, 60, settings=S)
    other = Settings(env="test", jwt_signing_key="another-key-0123456789-012345678")
    with pytest.raises(InvalidToken):
        verify_token(good, AUD_GATEWAY, other)


def test_password_hashing():
    h = hash_password("correct horse")
    assert verify_password(h, "correct horse")
    assert not verify_password(h, "wrong")


def test_prod_refuses_dev_or_short_signing_key():
    with pytest.raises(ValueError):
        Settings(env="prod", jwt_signing_key="dev-only-change-me")
    with pytest.raises(ValueError):
        Settings(env="prod", jwt_signing_key="too-short")
    Settings(env="prod", jwt_signing_key="x" * 32)
