"""Per-session state the gateway needs on the hot path: step count, rate window,
recent actions, and the provenance taint set (untrusted content read so far).

ponytail: in-process LRU. With several gateway replicas this moves to Redis,
keyed the same way (PRODUCTION.md §3).
"""

import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from threatlens.core.schemas import ActionEvent, ContentItem, Provenance

MAX_TAINT_IDS = 20


@dataclass
class Taint:
    content_id: str
    injection_score: float
    step: int
    techniques: list[str]
    source: str = ""


@dataclass
class SessionState:
    agent_id: str
    session_id: str
    step: int = 0
    times: deque = field(default_factory=lambda: deque(maxlen=1000))
    history: deque = field(default_factory=lambda: deque(maxlen=50))  # recent ActionEvents
    taints: list[Taint] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)  # runtime hosts seen for this session
    last_seen: float = field(default_factory=time.monotonic)

    def actions_last_minute(self) -> int:
        cutoff = time.monotonic() - 60
        return sum(1 for t in self.times if t >= cutoff)

    def provenance(self) -> Provenance:
        """Provenance for the action about to happen (step + 1).

        steps_since_taint = 1 means the tainted content was read by the action right before this one.
        """
        if not self.taints:
            return Provenance()
        recent = self.taints[-MAX_TAINT_IDS:]
        return Provenance(
            tainted_by=[t.content_id for t in recent],
            steps_since_taint=self.step + 1 - recent[-1].step,
        )

    def record(self, event: ActionEvent) -> None:
        self.step += 1
        self.times.append(time.monotonic())
        self.history.append(event)
        if event.runtime.host:
            self.hosts.add(event.runtime.host)
        self.last_seen = time.monotonic()

    def taint(self, item: ContentItem) -> None:
        self.taints.append(Taint(item.id, item.injection_score, self.step, list(item.techniques), item.source))
        self.last_seen = time.monotonic()


class SessionStore:
    def __init__(self, max_sessions: int = 5000, idle_ttl_s: float = 2 * 3600) -> None:
        self._sessions: OrderedDict[tuple[str, str], SessionState] = OrderedDict()
        self.max_sessions = max_sessions
        self.idle_ttl_s = idle_ttl_s

    def get(self, agent_id: str, session_id: str) -> SessionState:
        key = (agent_id, session_id)  # a session id can't be borrowed across agents
        s = self._sessions.get(key)
        if s is None or time.monotonic() - s.last_seen > self.idle_ttl_s:
            s = SessionState(agent_id, session_id)
            self._sessions[key] = s
        self._sessions.move_to_end(key)
        while len(self._sessions) > self.max_sessions:
            self._sessions.popitem(last=False)
        return s

    def for_agent(self, agent_id: str) -> list[SessionState]:
        return [s for (a, _), s in self._sessions.items() if a == agent_id]
