# Same image runs locally (docker compose) and on Render's free plan.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml ./
COPY threatlens ./threatlens
COPY threatlens_sdk ./threatlens_sdk
RUN pip install .
COPY roles ./roles
COPY catalog ./catalog

# Bake the embedding model into the image: Render's free plan has no persistent disk.
RUN python -c "from threatlens.detection.embedder import warm; warm('sentence-transformers/all-MiniLM-L6-v2', '/app/models')"

RUN useradd --create-home app && chown -R app /app
USER app

EXPOSE 8000
# Render injects $PORT; locally it defaults to 8000.
CMD ["sh", "-c", "uvicorn threatlens.api.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
