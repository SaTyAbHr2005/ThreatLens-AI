import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from threatlens.api.main import app
from threatlens.core.config import Settings
from threatlens.core.http import check_admin_key


@pytest.fixture
def client():
    with TestClient(app) as c:  # fresh in-memory registry per test (no DB in unit tests)
        yield c


def _create(client, agent_id, role):
    r = client.post("/v1/agents", json={"agent_id": agent_id, "role": role, "owner": f"{role}@corp.example"})
    assert r.status_code == 201, r.text
    return r.json()["token"]["token"]


def test_roles_and_agent_lifecycle(client):
    assert {r["role"] for r in client.get("/v1/roles").json()} == {"procurement", "hr", "finance", "support"}

    token = _create(client, "procurement-agent", "procurement")
    assert client.get("/v1/agents/procurement-agent").json()["status"] == "active"
    assert client.post("/v1/agents", json={"agent_id": "procurement-agent", "role": "procurement",
                                           "owner": "x@corp.example"}).status_code == 409

    r = client.post("/v1/agents/token/refresh", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json()["token"] != token


def test_delegation_over_http(client):
    support = _create(client, "support-agent", "support")
    _create(client, "finance-agent", "finance")
    hr = _create(client, "hr-agent", "hr")

    ok = client.post("/v1/agents/support-agent/delegate", json={"callee_id": "finance-agent"},
                     headers={"Authorization": f"Bearer {support}"})
    assert ok.status_code == 200
    assert ok.json()["claims"]["chain"] == ["support-agent", "finance-agent"]

    denied = client.post("/v1/agents/hr-agent/delegate", json={"callee_id": "finance-agent"},
                         headers={"Authorization": f"Bearer {hr}"})
    assert denied.status_code == 403

    # A token can't be used to delegate on behalf of a different agent.
    spoof = client.post("/v1/agents/support-agent/delegate", json={"callee_id": "finance-agent"},
                        headers={"Authorization": f"Bearer {hr}"})
    assert spoof.status_code == 403

    assert client.post("/v1/agents/support-agent/delegate", json={"callee_id": "finance-agent"}).status_code == 401


def test_amendment_over_http(client):
    r = client.post("/v1/roles/procurement/amendments", json={
        "changes": {"allowed_tools": {"add": ["logistics_api.track"]}},
        "reason": "Track shipments for open POs",
        "signer": "lead@corp.example",
    })
    assert r.status_code == 201, r.text
    detail = client.get("/v1/roles/procurement").json()
    assert detail["contract"]["version"] == 2 and len(detail["amendments"]) == 1

    bad = client.post("/v1/roles/procurement/amendments", json={
        "changes": {"role": "hr"}, "reason": "nope", "signer": "lead@corp.example"})
    assert bad.status_code == 422
    assert client.get("/v1/roles/astronaut").status_code == 404


def test_draft_without_llm_returns_template(client):
    r = client.post("/v1/roles/draft", json={"description": "An agent that answers IT helpdesk questions.",
                                             "owner": "it@corp.example"})
    assert r.status_code == 200 and r.json()["source"] == "template"


def test_admin_key_rules():
    check_admin_key(Settings(env="dev"), None)  # dev, no key configured: open
    with pytest.raises(HTTPException) as e:
        check_admin_key(Settings(env="prod", jwt_signing_key="k" * 40), None)
    assert e.value.status_code == 503
    keyed = Settings(env="prod", jwt_signing_key="k" * 40, admin_api_key="s3cret")
    with pytest.raises(HTTPException) as e:
        check_admin_key(keyed, "wrong")
    assert e.value.status_code == 401
    check_admin_key(keyed, "s3cret")
