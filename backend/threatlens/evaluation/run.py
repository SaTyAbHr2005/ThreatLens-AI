"""Run the evaluation lab and write the results file the Console's Evaluation page reads.

    python -m threatlens.evaluation.run [--benign 150] [--attacks 30] [--seed 7] [--save-weights]

1. Train set (seed): shadow pass → fit fusion weights on its labeled signals.
2. Test set (seed + 1, may hold unseen domains and hiding techniques):
   shadow pass → ablation table; enforced pass → outcome metrics.
3. The M8 scenario suite (A1–A7, B1–B2) on a fresh stack, as a regression check.
"""

import argparse
import asyncio
import json
import time
from pathlib import Path

from threatlens.core.config import Settings, get_settings
from threatlens.core.schemas import utcnow
from threatlens.detection import CachedEmbedder, make_embedder
from threatlens.fusion import Weights
from threatlens.fusion.model import fit_logistic
from threatlens.sim.runner import ScenarioRunner
from threatlens.sim.scenarios import SCENARIOS, run_scenario

from .dataset import generate
from .harness import Harness, SessionTrace
from .metrics import MATCHED_FPR, THRESHOLD, ablation, outcomes


async def _pass(settings, embedder, weights, sessions, *, shadow: bool) -> list[SessionTrace]:
    h = Harness(settings, embedder, weights, shadow=shadow)
    await h.start()
    return await h.run(sessions)


def _fit(traces: list[SessionTrace]) -> Weights:
    acts = [a for t in traces for a in t.actions if not a.warmup and a.signals]
    rows = [{s.signal.value: s.value for s in a.signals} for a in acts]
    return fit_logistic(rows, [int(a.malicious) for a in acts], source="fitted by the evaluation lab")


async def scenario_suite(settings, embedder) -> list[dict]:
    out = []
    for sid in SCENARIOS:
        h = Harness(settings, embedder)  # a fresh stack per scenario: no shared history
        await h.start()
        r = await run_scenario(ScenarioRunner(h.registry, h.gateway, h.fusion, h.sink), sid)
        await h.bus.drain()
        out.append({"id": sid, "name": r.name, "passed": r.passed, "checks": r.checks})
    return out


async def evaluate(settings: Settings, *, embedder: CachedEmbedder | None = None, seed: int = 7,
                   benign_per_role: int = 150, attacks_per_scenario: int = 30) -> dict:
    t0 = time.perf_counter()
    embedder = embedder or make_embedder(settings.embedding_backend, settings.embedding_model, settings.models_dir)
    production = Weights.load(settings.fusion_weights_path)
    train = generate(seed, benign_per_role, attacks_per_scenario)
    test = generate(seed + 1, benign_per_role, attacks_per_scenario, held_out=True)

    fitted = _fit(await _pass(settings, embedder, production, train, shadow=True))
    test_shadow = await _pass(settings, embedder, production, test, shadow=True)
    test_enforced = await _pass(settings, embedder, production, test, shadow=False)

    rows = ablation(test_shadow, production)
    fitted_row = ablation(test_shadow, fitted)[-1]
    rows.append({**fitted_row, "config": "full_fitted", "description": "All nine signals, weights fitted on the train set"})
    return {
        "generated_at": utcnow().isoformat(),
        "seed": seed,
        "dataset": {
            "train_sessions": len(train), "test_sessions": len(test),
            "test_benign_actions": sum(1 for t in test_shadow if t.label == "benign" for a in t.actions if not a.warmup),
            "test_attack_sessions": sum(1 for t in test if t.label == "attack"),
            "test_held_out_variants": sum(1 for t in test if t.novel),
        },
        "embedder": embedder.name,
        "weights": production.source,
        "threshold": THRESHOLD,
        "matched_fpr": MATCHED_FPR,
        "ablation": rows,
        "outcomes": outcomes(test_enforced),
        "fitted_weights": {"weights": fitted.weights, "bias": fitted.bias},
        "scenarios": await scenario_suite(settings, embedder),
        "duration_s": round(time.perf_counter() - t0, 1),
    }


def save(result: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")


def load_latest(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def summary(r: dict) -> str:
    lines = [f"{'config':<18}{'detect@60':>10}{'FPR@60':>8}{'detect@2%FPR':>14}{'held-out':>10}"]
    for row in r["ablation"]:
        a, m = row["at_threshold"], row["at_matched_fpr"]
        lines.append(f"{row['config']:<18}{a['detection_rate']:>10.2f}{a['false_positive_rate']:>8.2f}"
                     f"{m['detection_rate']:>14.2f}{a['held_out_variant_detection_rate']:>10.2f}")
    o = r["outcomes"]
    lines += ["", f"legit work preserved {o['legit_work_preserved']:.3f} · malicious actions blocked "
                  f"{o['malicious_actions_blocked']:.3f} · exfil bytes {o['exfil_bytes_reached_sink']} · "
                  f"attribution {o['attribution_accuracy']:.3f}",
              f"latency score p50/p95 {o['latency_ms']['score_p50']}/{o['latency_ms']['score_p95']} ms · "
              f"scenarios {sum(s['passed'] for s in r['scenarios'])}/{len(r['scenarios'])} pass · {r['duration_s']}s"]
    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(description="ThreatLens evaluation lab")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--benign", type=int, default=150, help="benign sessions per role")
    p.add_argument("--attacks", type=int, default=30, help="instances per attack scenario")
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--save-weights", action="store_true", help="write the fitted weights for production use")
    args = p.parse_args()
    settings = get_settings()
    result = asyncio.run(evaluate(settings, seed=args.seed, benign_per_role=args.benign,
                                  attacks_per_scenario=args.attacks))
    save(result, args.out or settings.eval_results_path)
    if args.save_weights:
        Weights(**result["fitted_weights"], source="fitted by the evaluation lab").save(settings.fusion_weights_path)
    print(summary(result))


if __name__ == "__main__":
    main()
