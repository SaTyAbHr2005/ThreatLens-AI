# Same image runs locally (docker compose) and on Render's free plan.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml ./
COPY threatlens ./threatlens
RUN pip install .

RUN useradd --create-home app && chown -R app /app
USER app

EXPOSE 8000
# Render injects $PORT; locally it defaults to 8000.
CMD ["sh", "-c", "uvicorn threatlens.api.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
