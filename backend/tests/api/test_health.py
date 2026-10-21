from fastapi.testclient import TestClient

from threatlens.api.main import app


def test_health_reports_degraded_db_without_failing():
    # No database reachable in unit tests: the API must still start and answer,
    # so Render's health check doesn't restart-loop during an Atlas hiccup.
    with TestClient(app) as client:
        r = client.get("/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in {"ok", "degraded"}
    assert isinstance(body["llm"], list)
