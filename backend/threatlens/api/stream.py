"""WebSocket hub `/v1/stream`: live actions, alerts, containment and arena progress.

The browser can't set headers on a WebSocket, so the first message authenticates:
{"token": "<analyst JWT>"} or {"admin_key": "..."} (open in dev when no key is set).
A slow client never slows the gateway: each has a bounded queue, oldest dropped first.

ponytail: one process. With several API instances the hub reads from the event
stream (Kafka / Redis pub-sub) instead of the in-process bus.
"""

import asyncio
import contextlib
import json
import logging

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from threatlens.core.bus import EventBus, Topics
from threatlens.core.config import get_settings
from threatlens.core.http import operator_principal

log = logging.getLogger(__name__)

TOPICS = (Topics.action_scored, Topics.alert_raised, Topics.alert_updated, Topics.containment_changed,
          Topics.content_scanned, Topics.arena_progress)
QUEUE = 500
AUTH_TIMEOUT_S = 5
RECENT = 25  # actions replayed to a client that just connected


def _json(payload) -> object:
    return payload.model_dump(mode="json") if hasattr(payload, "model_dump") else payload


class StreamHub:
    def __init__(self) -> None:
        self.clients: set[asyncio.Queue] = set()

    def attach(self, bus: EventBus):
        offs = []
        for topic in TOPICS:
            async def handler(payload, topic=topic):
                self.broadcast(json.dumps({"topic": topic, "data": _json(payload)}, default=str))
            offs.append(bus.subscribe(topic, handler))
        return offs

    def broadcast(self, message: str) -> None:
        for q in self.clients:
            if q.full():
                q.get_nowait()  # drop the oldest for a slow client
            q.put_nowait(message)


def recent_actions(replay, n: int = RECENT) -> list[dict]:
    events = [e for steps in replay.sessions.values() for e in steps[-n:]]
    return sorted(events, key=lambda e: e["ts"])[-n:]


router = APIRouter()


@router.websocket("/v1/stream")
async def stream(ws: WebSocket):
    await ws.accept()
    try:
        hello = json.loads(await asyncio.wait_for(ws.receive_text(), AUTH_TIMEOUT_S))
        token = hello.get("token")
        who = operator_principal(get_settings(), hello.get("admin_key"), f"Bearer {token}" if token else None)
    except (asyncio.TimeoutError, ValueError, AttributeError, HTTPException, WebSocketDisconnect):
        with contextlib.suppress(Exception):
            await ws.close(code=4401, reason="authenticate first: {\"token\": \"<analyst JWT>\"}")
        return

    hub: StreamHub = ws.app.state.stream
    q: asyncio.Queue = asyncio.Queue(QUEUE)
    hub.clients.add(q)
    await ws.send_text(json.dumps({"topic": "hello", "data": {"as": who, "topics": list(TOPICS)}}))
    # The latest actions first, oldest to newest, so a reloaded console isn't an empty feed.
    for event in recent_actions(ws.app.state.replay):
        await ws.send_text(json.dumps({"topic": Topics.action_scored, "data": event}, default=str))

    async def drain_incoming():  # returns when the client leaves
        with contextlib.suppress(WebSocketDisconnect, RuntimeError):
            while True:
                await ws.receive_text()

    reader = asyncio.create_task(drain_incoming())
    try:
        while not reader.done():
            getter = asyncio.create_task(q.get())
            done, _ = await asyncio.wait({getter, reader}, return_when=asyncio.FIRST_COMPLETED)
            if getter in done:
                await ws.send_text(getter.result())
            else:
                getter.cancel()
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.clients.discard(q)
        reader.cancel()
