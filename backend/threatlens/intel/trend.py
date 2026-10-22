"""Fleet threat trend: per-agent drift and risk by minute, plus one combined fleet score.

Fleet score per minute = 0.6 · highest agent drift + 0.4 · average agent drift:
one badly drifting agent dominates, but a fleet-wide rise shows too.

ponytail: live window in memory (6 h). Longer history comes from Atlas `agent_minutely`
(90-day TTL), which the M5 sink already writes.
"""

from collections import OrderedDict
from datetime import datetime, timedelta

from threatlens.core.schemas import ActionEvent, utcnow

KEEP_MINUTES = 360


def minute_of(ts: datetime) -> datetime:
    return ts.replace(second=0, microsecond=0)


def fleet_score(drifts: list[float]) -> float:
    return round(0.6 * max(drifts) + 0.4 * sum(drifts) / len(drifts), 2) if drifts else 0.0


class TrendBook:
    def __init__(self) -> None:
        self._agents: dict[str, OrderedDict[datetime, dict]] = {}

    def add(self, event: ActionEvent, drift: float) -> None:
        series = self._agents.setdefault(event.agent_id, OrderedDict())
        m = minute_of(event.ts)
        b = series.setdefault(m, {"max_risk": 0.0, "count": 0, "alerting": 0, "drift": 0.0})
        b["count"] += 1
        b["alerting"] += 1 if event.alert_id else 0
        b["max_risk"] = max(b["max_risk"], event.risk or 0.0)
        b["drift"] = drift
        cutoff = minute_of(utcnow()) - timedelta(minutes=KEEP_MINUTES)
        while series and next(iter(series)) < cutoff:
            series.popitem(last=False)

    def query(self, minutes: int = 60) -> dict:
        end = minute_of(utcnow())
        axis = [end - timedelta(minutes=i) for i in range(minutes - 1, -1, -1)]
        agents, last_drift = {}, {}
        for agent_id, series in self._agents.items():
            points, carried = [], None
            earlier = [b["drift"] for t, b in series.items() if t < axis[0]]
            carried = earlier[-1] if earlier else None
            for t in axis:
                b = series.get(t)
                carried = b["drift"] if b else carried
                points.append({"minute": t.isoformat(), "drift": carried,
                               "max_risk": b["max_risk"] if b else None, "count": b["count"] if b else 0})
            agents[agent_id] = points
            last_drift[agent_id] = carried
        fleet = []
        for i, t in enumerate(axis):
            drifts = [p[i]["drift"] for p in agents.values() if p[i]["drift"] is not None]
            fleet.append({"minute": t.isoformat(), "score": fleet_score(drifts), "agents": len(drifts)})
        return {"minutes": minutes, "agents": agents, "fleet": fleet,
                "now": {"fleet_score": fleet[-1]["score"] if fleet else 0.0,
                        "drift": {a: d for a, d in last_drift.items() if d is not None}}}
