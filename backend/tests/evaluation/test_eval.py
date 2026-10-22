"""M9: the dataset, both harness passes, the ablation's headline row, and the API."""

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatlens.core.config import Settings, get_settings
from threatlens.evaluation import router as eval_router
from threatlens.evaluation.dataset import generate
from threatlens.evaluation.harness import Harness
from threatlens.evaluation.run import evaluate, save

S = Settings(env="test", jwt_signing_key="eval-test-signing-key-0123456789-abcdefgh", embedding_backend="hashing")


def test_dataset_is_reproducible_and_holds_out_variants():
    a, b = generate(3, 5, 8), generate(3, 5, 8)
    assert [s.id for s in a] == [s.id for s in b]
    assert not any(s.novel for s in a)  # training never sees the held-out domain or technique
    test = generate(4, 5, 30, held_out=True)
    assert any(s.novel for s in test)
    attacks = [s for s in test if s.label == "attack"]
    assert all(any(st.malicious for st in s.steps) for s in attacks)
    assert all(any(st.is_cause for st in s.steps) for s in attacks if s.scenario in ("A1", "A2"))


async def test_shadow_pass_observes_everything_and_contains_nobody():
    h = Harness(S, shadow=True)
    await h.start()
    traces = await h.run(generate(5, 3, 3, held_out=True))
    assert all(t.final_status == "active" for t in traces)
    assert all(a.decision != "quarantine" for t in traces for a in t.actions)
    assert all(a.signals for t in traces for a in t.actions)  # every action was scored
    assert sum(t.exfil_bytes for t in traces) > 0  # shadow never blocks, so the sink saw the attempts


@pytest.fixture(scope="module")
def result():
    return asyncio.run(evaluate(S, benign_per_role=10, attacks_per_scenario=6))


def test_iam_only_catches_nothing_and_full_catches_attacks(result):
    rows = {r["config"]: r for r in result["ablation"]}
    assert rows["iam_only"]["at_threshold"]["detection_rate"] == 0.0  # every token was valid
    full = rows["full"]["at_threshold"]
    assert full["detection_rate"] >= 0.9
    assert full["false_positive_rate"] <= 0.05


def test_enforced_outcomes(result):
    o = result["outcomes"]
    assert o["exfil_bytes_reached_sink"] == 0
    assert o["attribution_accuracy"] == 1.0
    assert o["legit_work_preserved"] >= 0.95
    assert o["malicious_actions_blocked"] >= 0.9


def test_scenario_suite_passes(result):
    failed = [s for s in result["scenarios"] if not s["passed"]]
    assert failed == []


def test_latest_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "eval_results_path", tmp_path / "r.json")
    app = FastAPI()
    app.include_router(eval_router.router)
    client = TestClient(app)
    assert client.get("/v1/eval/latest").status_code == 404
    save({"ablation": [], "outcomes": {}}, tmp_path / "r.json")
    body = client.get("/v1/eval/latest").json()
    assert body["ablation"] == [] and body["running"] is False
