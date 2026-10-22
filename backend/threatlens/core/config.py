"""Typed settings loaded from environment variables (and `.env` in development)."""

from functools import lru_cache
from pathlib import Path
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

    # Operator access to management endpoints until analyst login lands (M10).
    # Required in prod; optional in dev/test.
    admin_api_key: str | None = None

    # Agents
    agent_mode: Literal["llm", "replay"] = "replay"
    roles_dir: Path = Path(__file__).resolve().parents[2] / "roles"  # backend/roles
    catalog_dir: Path = Path(__file__).resolve().parents[2] / "catalog"  # backend/catalog
    # Fitted risk-fusion weights (written by the evaluation lab, M9). Missing = hand-tuned defaults.
    fusion_weights_path: Path = Path(__file__).resolve().parents[2] / "catalog" / "fusion_weights.json"

    # Where the gateway forwards allowed tool calls (POST {url}/tools/{tool}).
    # The mock enterprise (M8) serves them; production points at real tool servers.
    tools_base_url: str | None = None

    # Free LLM providers (all optional; the router skips any without a key/url)
    groq_api_key: str | None = None
    groq_model: str = "openai/gpt-oss-120b"  # verified: chat + tool calling
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.5-flash-lite"  # verified: chat + tool calling
    openrouter_api_key: str | None = None
    openrouter_models: str = ""  # comma-separated free model ids
    ollama_url: str | None = None
    ollama_model: str = "llama3.1"
    # Injection classifier served by Groq (uses GROQ_API_KEY); empty disables it.
    prompt_guard_model: str = "meta-llama/llama-prompt-guard-2-86m"

    # Role-conformance embeddings (S1). "hashing" needs no model download (offline / tests).
    embedding_backend: Literal["fastembed", "hashing"] = "fastembed"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    models_dir: Path = Path(__file__).resolve().parents[2] / "models"  # baked into the Docker image

    # Other services
    ml_service_url: str | None = None
    discord_webhook_url: str | None = None
    resend_api_key: str | None = None
    cors_origins: str = "http://localhost:5173"
    console_url: str = "http://localhost:5173"  # links in Discord alerts point here (the Vercel URL in prod)
    fail_mode_sensitive: Literal["closed", "open"] = "closed"

    @property
    def openrouter_model_list(self) -> list[str]:
        return [m.strip() for m in self.openrouter_models.split(",") if m.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @model_validator(mode="after")
    def _strong_key_in_prod(self) -> "Settings":
        if self.env == "prod" and (self.jwt_signing_key == DEV_JWT_KEY or len(self.jwt_signing_key) < 32):
            raise ValueError("JWT_SIGNING_KEY must be a random value of at least 32 characters in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
