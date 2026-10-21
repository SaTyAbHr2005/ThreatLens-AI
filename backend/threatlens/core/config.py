"""Typed settings loaded from environment variables (and `.env` in development)."""

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_JWT_KEY = "dev-only-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    env: Literal["dev", "test", "prod"] = "dev"

    # Database
    mongo_uri: str = "mongodb://localhost:27017"  # set to your Atlas mongodb+srv:// URI
    mongo_db: str = "threatlens"
    mongo_timeout_ms: int = 5000

    # Tokens
    jwt_signing_key: str = DEV_JWT_KEY
    jwt_issuer: str = "threatlens"
    agent_token_ttl_s: int = 900
    downstream_token_ttl_s: int = 60
    analyst_token_ttl_s: int = 8 * 3600

    # Agents
    agent_mode: Literal["llm", "replay"] = "replay"

    # Free LLM providers (all optional; the router skips any without a key/url)
    groq_api_key: str | None = None
    groq_model: str = "llama-3.3-70b-versatile"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-2.5-flash"
    openrouter_api_key: str | None = None
    openrouter_models: str = ""  # comma-separated free model ids
    ollama_url: str | None = None
    ollama_model: str = "llama3.1"

    # Other services
    ml_service_url: str | None = None
    discord_webhook_url: str | None = None
    resend_api_key: str | None = None
    cors_origins: str = "http://localhost:5173"
    fail_mode_sensitive: Literal["closed", "open"] = "closed"

    @property
    def openrouter_model_list(self) -> list[str]:
        return [m.strip() for m in self.openrouter_models.split(",") if m.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @model_validator(mode="after")
    def _no_dev_key_in_prod(self) -> "Settings":
        if self.env == "prod" and self.jwt_signing_key == DEV_JWT_KEY:
            raise ValueError("JWT_SIGNING_KEY must be set in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
