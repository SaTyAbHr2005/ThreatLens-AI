import os

# Unit tests are hermetic: no real database or LLM keys, whatever is in .env.
# (Environment variables take priority over .env in pydantic-settings.)
os.environ.update(
    ENV="test",
    MONGO_URI="mongodb://127.0.0.1:1",
    MONGO_TIMEOUT_MS="300",
    GROQ_API_KEY="",
    GEMINI_API_KEY="",
    OPENROUTER_API_KEY="",
    OLLAMA_URL="",
    ADMIN_API_KEY="",
    JWT_SIGNING_KEY="unit-test-signing-key-0123456789-abcdefgh",
)
