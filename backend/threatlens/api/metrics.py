"""`GET /metrics` in the Prometheus text format: decisions, scoring latency, cache, memory.

Aggregate counts only (no agent ids, no content), so it is safe to leave unauthenticated
for a scraper. Written by hand: a few counters and one histogram don't need a client library.
"""

import os
from collections import Counter

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from threatlens.core.bus import EventBus, Topics
from threatlens.core.schemas import ActionEvent

BUCKETS_MS = (1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000)


class Metrics:
    def __init__(self) -> None:
        self.decisions: Counter = Counter()  # (decision, shadow)
        self.alerts = 0
        self.containment: Counter = Counter()  # to_status
        self.score_buckets = [0] * len(BUCKETS_MS)
        self.score_sum = 0.0
        self.score_count = 0

    def attach(self, bus: EventBus):
        return [bus.subscribe(Topics.action_scored, self._on_action),
                bus.subscribe(Topics.alert_raised, self._on_alert),
                bus.subscribe(Topics.containment_changed, self._on_containment)]

    async def _on_action(self, e: ActionEvent) -> None:
        self.decisions[(e.decision.value if e.decision else "none", e.shadow)] += 1
        if e.score_ms is not None:
            self.score_sum += e.score_ms
            self.score_count += 1
            for i, b in enumerate(BUCKETS_MS):
                if e.score_ms <= b:
                    self.score_buckets[i] += 1

    async def _on_alert(self, _) -> None:
        self.alerts += 1

    async def _on_containment(self, d) -> None:
        self.containment[d.to_status.value if d.to_status else "unknown"] += 1


def _rss_bytes() -> int | None:
    try:  # Linux (Docker, Render)
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, AttributeError):
        return None


router = APIRouter()


@router.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
def metrics(request: Request) -> str:
    st = request.app.state
    m: Metrics = st.metrics
    out = ["# TYPE threatlens_decisions_total counter"]
    out += [f'threatlens_decisions_total{{decision="{d}",shadow="{str(s).lower()}"}} {n}'
            for (d, s), n in sorted(m.decisions.items())]
    out += ["# TYPE threatlens_score_ms histogram"]
    out += [f'threatlens_score_ms_bucket{{le="{b}"}} {n}' for b, n in zip(BUCKETS_MS, m.score_buckets)]
    out += [f'threatlens_score_ms_bucket{{le="+Inf"}} {m.score_count}',
            f"threatlens_score_ms_sum {m.score_sum:.3f}", f"threatlens_score_ms_count {m.score_count}",
            "# TYPE threatlens_alerts_raised_total counter", f"threatlens_alerts_raised_total {m.alerts}",
            "# TYPE threatlens_containment_changes_total counter"]
    out += [f'threatlens_containment_changes_total{{to="{s}"}} {n}' for s, n in sorted(m.containment.items())]
    statuses = Counter(a.status.value for a in st.registry.agents())
    out += ["# TYPE threatlens_agents gauge"]
    out += [f'threatlens_agents{{status="{s}"}} {n}' for s, n in sorted(statuses.items())]
    emb = st.detector.embedder
    out += ["# TYPE threatlens_embedding_cache_total counter",
            f'threatlens_embedding_cache_total{{result="hit"}} {emb.hits}',
            f'threatlens_embedding_cache_total{{result="miss"}} {emb.misses}',
            "# TYPE threatlens_stream_clients gauge", f"threatlens_stream_clients {len(st.stream.clients)}"]
    rss = _rss_bytes()
    if rss is not None:
        out += ["# TYPE process_resident_memory_bytes gauge", f"process_resident_memory_bytes {rss}"]
    return "\n".join(out) + "\n"
