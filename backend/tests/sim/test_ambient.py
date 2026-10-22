"""Routine traffic: ordinary in-role work through the real stack raises nothing and respects containment."""

from datetime import timedelta

from threatlens.api.stream import recent_actions
from threatlens.core.schemas import AgentStatus, utcnow
from threatlens.intel.trend import TrendBook, minute_of
from threatlens.sim.ambient import ROLES, AmbientTraffic, agent_id


async def test_routine_work_is_allowed_and_raises_no_alert(runner):
    traffic = AmbientTraffic(runner.registry, runner.gateway, seed=3)
    results = [await traffic.step() for _ in range(80)]  # 20 actions per role, several sessions each
    assert all(r is not None and r.decision.value == "allow" for r in results), \
        [(r.event_id, r.decision) for r in results if r and r.decision.value != "allow"]
    assert await runner.fusion.alerts.list() == []
    assert {runner.registry.agent(agent_id(r)).status for r in ROLES} == {AgentStatus.active}


async def test_contained_agent_is_left_alone(runner):
    traffic = AmbientTraffic(runner.registry, runner.gateway, seed=3)
    await traffic.step()  # creates the procurement agent
    await runner.registry.set_status(agent_id("procurement"), AgentStatus.quarantined)
    traffic._turn = 0
    assert await traffic.step() is None


def test_recent_actions_are_the_latest_oldest_first():
    class Replay:
        sessions = {"a": [{"ts": "2026-10-23T10:00:01"}, {"ts": "2026-10-23T10:00:05"}],
                    "b": [{"ts": "2026-10-23T10:00:03"}]}

    assert [e["ts"][-2:] for e in recent_actions(Replay, n=2)] == ["03", "05"]


async def test_trend_reloads_recent_minutes_from_atlas():
    now = minute_of(utcnow())
    rows = [{"agent_id": "hr-agent-routine", "minute": now - timedelta(minutes=m), "drift": 3.0, "max_risk": 9.0,
             "count": 2, "alerting": 0} for m in (5, 2)]

    class Cursor:
        def sort(self, *_):
            return self

        def __aiter__(self):
            async def gen():
                for r in rows:
                    yield r
            return gen()

    class Db:
        def __getitem__(self, _):
            return self

        def find(self, *_):
            return Cursor()

    book = TrendBook()
    await book.load(Db())
    q = book.query(10)
    assert q["now"]["drift"] == {"hr-agent-routine": 3.0}
    assert sum(p["count"] for p in q["agents"]["hr-agent-routine"]) == 4
