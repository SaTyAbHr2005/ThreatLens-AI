"""Routine traffic: four agents doing ordinary in-role work, so a fresh demo isn't an empty screen.

Off by default; AMBIENT_TRAFFIC=true turns it on (the free-tier demo does). Every step goes
through the real gateway and detector. It's the same benign work the evaluation lab measures
(0 false alerts per 1,000 legitimate actions), so it also shows the quiet side of the product:
agents working inside their role raise nothing. An agent an analyst contained is left alone.

ponytail: one in-process loop. With several API instances, run it in exactly one of them.
"""

import asyncio
import contextlib
import logging
import random

from threatlens.core.schemas import AgentStatus, RuntimeFingerprint
from threatlens.evaluation.dataset import _benign_steps
from threatlens.gateway.service import ToolCallFailed
from threatlens.identity import AgentExists

from .runner import GRANTS

log = logging.getLogger(__name__)

ROLES = ("procurement", "hr", "finance", "support")


def agent_id(role: str) -> str:
    return f"{role}-agent-routine"


class AmbientTraffic:
    def __init__(self, registry, gateway, *, interval_s: float = 12.0, seed: int | None = None):
        self.registry = registry
        self.gateway = gateway
        self.interval_s = interval_s
        self.rng = random.Random(seed)
        self._turn = 0
        self._sessions: dict[str, tuple[str, str, int]] = {}  # agent -> (session id, token, steps left)
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self.interval_s * self.rng.uniform(0.5, 1.5))
            try:
                await self.step()
            except Exception:
                log.exception("routine traffic step failed")

    async def step(self):
        """One ordinary action by the next agent in turn. Returns the gateway result, or None if skipped."""
        role = ROLES[self._turn % len(ROLES)]
        self._turn += 1
        agent = agent_id(role)
        with contextlib.suppress(AgentExists):
            await self.registry.create_agent(agent, role, f"{role}-team@corp.example", GRANTS.get(role))
        if self.registry.agent(agent).status != AgentStatus.active:
            self._sessions.pop(agent, None)
            return None  # an analyst's containment stands until they release it

        session, token, left = self._sessions.get(agent) or (None, None, 0)
        if left <= 0:  # a new work session of 4-8 actions, with a fresh token (they last 15 minutes)
            session = f"routine-{role}-{self.rng.getrandbits(32):08x}"
            token, left = self.registry.issue_token(agent).token, self.rng.randint(4, 8)
        self._sessions[agent] = (session, token, left - 1)

        step = _benign_steps(role, self.rng, 1)[0]
        try:
            return await self.gateway.tool_call(token, session, step.tool, dict(step.args),
                                                RuntimeFingerprint(host=f"{role}-worker", sdk="python"))
        except ToolCallFailed as e:
            return e.result  # the tool itself failed; the action was still scored
        except Exception:
            self._sessions.pop(agent, None)  # e.g. token revoked or stale after an amendment: start clean
            raise
