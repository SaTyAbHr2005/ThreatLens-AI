"""`GET /v1/replay/{session_id}`: one agent session, step by step, for time-travel replay.

Recent sessions come from an in-memory buffer (works without a database); older ones
from Atlas `events` (kept 7 days). Each step carries its scores and decision; the
content the agent read, the session's alerts and the containment decisions come with it.
"""

from collections import OrderedDict

from fastapi import APIRouter, Depends, HTTPException, Request

from threatlens.core.bus import EventBus, Topics
from threatlens.core.db import C
from threatlens.core.http import require_operator
from threatlens.core.schemas import ActionEvent, ContentItem

MAX_SESSIONS, MAX_EVENTS, MAX_CONTENT = 500, 1000, 5000


class ReplayBuffer:
    def __init__(self) -> None:
        self.sessions: OrderedDict[str, list[dict]] = OrderedDict()
        self.content: OrderedDict[str, dict] = OrderedDict()

    def attach(self, bus: EventBus):
        return [bus.subscribe(Topics.action_scored, self._on_event),
                bus.subscribe(Topics.content_scanned, self._on_content)]

    async def _on_event(self, event: ActionEvent) -> None:
        steps = self.sessions.setdefault(event.session_id, [])
        self.sessions.move_to_end(event.session_id)
        steps.append(event.model_dump(mode="json"))
        del steps[:-MAX_EVENTS]
        while len(self.sessions) > MAX_SESSIONS:
            self.sessions.popitem(last=False)

    async def _on_content(self, item: ContentItem) -> None:
        self.content[item.id] = item.model_dump(mode="json")
        while len(self.content) > MAX_CONTENT:
            self.content.popitem(last=False)


def _doc(d: dict, ts_field: str) -> dict:
    """A stored row back in the API's JSON shape."""
    d["id"] = d.pop("_id")
    d[ts_field] = d[ts_field].isoformat()
    return d


router = APIRouter(prefix="/v1", tags=["replay"], dependencies=[Depends(require_operator)])


@router.get("/replay/{session_id}")
async def replay(session_id: str, request: Request):
    st = request.app.state
    buf: ReplayBuffer = st.replay
    db = st.db if st.persist else None
    events = list(buf.sessions.get(session_id, []))
    if not events and db is not None:
        events = [_doc(d, "ts") async for d in
                  db[C.events].find({"session_id": session_id}).sort("ts", 1).limit(MAX_EVENTS)]
    if not events:
        raise HTTPException(404, "no such session (sessions are kept 7 days)")

    content_ids = list(dict.fromkeys(cid for e in events for cid in e.get("provenance", {}).get("tainted_by", [])))
    content = [buf.content[c] for c in content_ids if c in buf.content]
    missing = [c for c in content_ids if c not in buf.content]
    if missing and db is not None:
        content += [_doc(d, "created_at") async for d in db[C.content_items].find({"_id": {"$in": missing}})]

    agents = sorted({e["agent_id"] for e in events})
    alerts = [a for agent in agents for a in await st.fusion.alerts.list(agent_id=agent, limit=200)
              if a.session_id == session_id]
    event_ids, alert_ids = {e["id"] for e in events}, {a.id for a in alerts}
    decisions = [d for agent in agents for d in await st.response.decisions.list(agent_id=agent, limit=200)
                 if d.event_id in event_ids or d.alert_id in alert_ids]
    return {
        "session_id": session_id,
        "agents": agents,
        "steps": events,
        "content": content,
        "alerts": [a.model_dump(mode="json") for a in alerts],
        "decisions": sorted((d.model_dump(mode="json") for d in decisions), key=lambda d: d["ts"]),
    }
