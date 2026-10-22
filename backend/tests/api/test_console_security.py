"""M10: Slider CAPTCHA, login anomaly, analyst login, stream, replay, metrics, rate limits."""

import math
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from threatlens.api.anomaly import LoginAnomalyModel
from threatlens.api.auth import Analyst
from threatlens.api.captcha import CaptchaAnswer, CaptchaVerifier, Point
from threatlens.api.main import app
from threatlens.api.ratelimit import RateLimiter
from threatlens.core.config import Settings
from threatlens.core.schemas import utcnow
from threatlens.core.security import hash_password

S = Settings(env="test", jwt_signing_key="console-test-signing-key-0123456789-abcd")
EMAIL, PASSWORD = "analyst@corp.example", "correct horse battery staple"


def human(target: float, ms: float = 1400, n: int = 40) -> list[dict]:
    """Ease-in-out drag with a little wobble, like a hand."""
    pts = []
    for i in range(n + 1):
        u = i / n
        pts.append({"t": ms * u, "x": target * (1 - math.cos(math.pi * u)) / 2, "y": 1.5 * math.sin(7 * u)})
    return pts


def robot(target: float, ms: float = 1400, n: int = 40) -> list[dict]:
    return [{"t": ms * i / n, "x": target * i / n, "y": 0.0} for i in range(n + 1)]


def answer(ch: dict, traj: list[dict]) -> CaptchaAnswer:
    return CaptchaAnswer(token=ch["token"], trajectory=[Point(**p) for p in traj])


# ---------------------------------------------------------------- CAPTCHA


def test_captcha_accepts_a_hand_and_rejects_a_script():
    v = CaptchaVerifier(S)
    ch = v.challenge()
    r = v.verify(answer(ch, human(ch["target"])))
    assert r.ok and r.speed_cv > 0.15
    ch = v.challenge()
    assert "scripted" in v.verify(answer(ch, robot(ch["target"]))).reason


def test_captcha_checks_target_speed_and_single_use():
    v = CaptchaVerifier(S)
    ch = v.challenge()
    assert not v.verify(answer(ch, human(ch["target"] - 40))).ok  # missed the gap
    ch = v.challenge()
    assert v.verify(answer(ch, human(ch["target"], ms=120))).reason == "too fast"
    ch = v.challenge()
    assert v.verify(answer(ch, human(ch["target"]))).ok
    assert v.verify(answer(ch, human(ch["target"]))).reason == "challenge already used"
    assert not v.verify(CaptchaAnswer(token="forged", trajectory=[Point(t=0, x=0), Point(t=1, x=1)])).ok


# ---------------------------------------------------------------- login anomaly


def test_login_anomaly_model():
    m = LoginAnomalyModel()
    normal = {"hour_shift": 1.0, "new_device": 0.0, "failures": 0.0, "solve_log_ms": math.log10(1700), "speed_cv": 0.7}
    assert not m.assess(normal).anomalous
    assert not m.assess({**normal, "new_device": 1.0}).anomalous  # a new laptop alone is fine
    odd = m.assess({**normal, "hour_shift": 10.0, "new_device": 1.0, "failures": 4.0})
    assert odd.anomalous and "recent failed attempts" in odd.reasons


# ---------------------------------------------------------------- API (one app for the module)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def login(c, password=PASSWORD, device="device-aaaa-1111", traj=None):
    ch = c.post("/v1/auth/captcha").json()
    return c.post("/v1/auth/login", json={"email": EMAIL, "password": password, "device_id": device,
                                          "captcha": {"token": ch["token"], "trajectory": traj or human(ch["target"])}})


def test_login_flow_and_analyst_as_actor(client):
    assert client.post("/v1/auth/analysts", json={"email": EMAIL, "name": "Ana", "password": PASSWORD}).status_code == 201
    assert login(client, password="wrong password").status_code == 401
    r = login(client)
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    auth = {"Authorization": f"Bearer {token}"}
    assert client.get("/v1/auth/me", headers=auth).json()["email"] == EMAIL
    assert client.get("/v1/alerts", headers={"Authorization": "Bearer nonsense"}).status_code == 401

    client.post("/v1/agents", json={"agent_id": "console-test-agent", "role": "support", "owner": "s@corp.example"})
    d = client.post("/v1/agents/console-test-agent/containment", headers=auth,
                    json={"action": "restrict", "reason": "checking", "actor": "someone-else@corp.example"}).json()
    assert d["actor"] == EMAIL  # the audit log records who was signed in, not what the body claimed


def test_anomalous_login_is_blocked(client):
    a = client.app.state.auth.store.get(EMAIL)
    a.login_hours = [(utcnow().hour + 10) % 24] * 10  # this account usually logs in 10 hours from now
    a.devices = ["known-device-hash"]
    r = login(client, device="brand-new-device-9")
    assert r.status_code == 403
    assert "a device this account has never used" in r.json()["detail"]["reasons"]


def test_public_demo_account(client):
    svc = client.app.state.auth
    assert client.get("/v1/auth/demo").status_code == 404  # hidden unless switched on
    demo, pw = "judge@demo.example", "a demo password for judges"
    old = svc.settings
    svc.settings = old.model_copy(update={"demo_analyst_email": demo, "demo_analyst_password": pw,
                                          "demo_analyst_public": True})
    try:
        svc.store._by_email[demo] = Analyst(email=demo, name="Demo analyst", password_hash=hash_password(pw))
        assert client.get("/v1/auth/demo").json() == {"email": demo, "password": pw}
        # Visitors share it: a usual hour and device from someone else must not block a new one.
        a = svc.store.get(demo)
        a.login_hours, a.devices = [(utcnow().hour + 10) % 24] * 10, ["known-device-hash"]
        ch = client.post("/v1/auth/captcha").json()
        r = client.post("/v1/auth/login", json={"email": demo, "password": pw, "device_id": "judge-device-2",
                                                "captcha": {"token": ch["token"], "trajectory": human(ch["target"])}})
        assert r.status_code == 200, r.text
        # Failures lock out per address, not the whole shared account.
        for _ in range(5):
            svc._failures[f"{demo}|203.0.113.9"].append(time.time())
        assert svc._recent_failures(f"{demo}|testclient") == 0
    finally:
        svc.settings = old


def test_scripted_captcha_blocks_login(client):
    ch = client.post("/v1/auth/captcha").json()
    r = client.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD, "device_id": "device-aaaa-1111",
                                            "captcha": {"token": ch["token"], "trajectory": robot(ch["target"])}})
    assert r.status_code == 400 and "scripted" in r.json()["detail"]


def test_stream_replay_and_metrics(client):
    with pytest.raises(WebSocketDisconnect) as e:
        with client.websocket_connect("/v1/stream") as ws:
            ws.send_json({"token": "not-a-jwt"})
            ws.receive_json()
    assert e.value.code == 4401

    with client.websocket_connect("/v1/stream") as ws:
        ws.send_json({})  # dev mode with no admin key configured: open
        assert ws.receive_json()["topic"] == "hello"
        run = client.post("/v1/sim/scenarios/A1/run").json()
        topics = {ws.receive_json()["topic"] for _ in range(6)}
    assert "action.scored" in topics

    session = run["alert"]["session_id"]
    rep = client.get(f"/v1/replay/{session}").json()
    assert len(rep["steps"]) >= 4
    assert rep["alerts"] and rep["content"]  # the poisoned PDF the agent read
    assert client.get("/v1/replay/no-such-session").status_code == 404

    text = client.get("/metrics").text
    assert "threatlens_decisions_total" in text and "threatlens_score_ms_count" in text
    assert 'threatlens_score_ms_count 0' not in text


def test_rate_limits():
    small = FastAPI()
    small.add_middleware(RateLimiter, per_min=3, auth_per_min=1)

    @small.get("/v1/x")
    def x():
        return {}

    @small.post("/v1/auth/captcha")
    def c():
        return {}

    t = TestClient(small)
    assert [t.get("/v1/x", headers={"X-Admin-Key": "k"}).status_code for _ in range(4)] == [200, 200, 200, 429]
    assert t.get("/v1/x", headers={"X-Admin-Key": "other"}).status_code == 200  # per credential
    assert [t.post("/v1/auth/captcha").status_code for _ in range(2)] == [200, 429]
