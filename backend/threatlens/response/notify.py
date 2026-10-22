"""Discord notifications for Step-up and Isolate decisions (free, via a channel webhook)."""

import logging
import time

import httpx

from threatlens.core.schemas import AgentStatus, Decision

log = logging.getLogger(__name__)

COLORS = {AgentStatus.step_up: 0xC9A23A, AgentStatus.quarantined: 0xC8323C}
TITLES = {AgentStatus.step_up: "held for step-up approval", AgentStatus.quarantined: "isolated"}
MIN_GAP_S = 30  # per agent, so one incident doesn't flood the channel


class DiscordNotifier:
    def __init__(self, webhook_url: str, *, console_url: str | None = None,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.url = webhook_url
        self.console_url = console_url
        self._client = httpx.AsyncClient(transport=transport, timeout=10)
        self._last: dict[str, float] = {}

    async def on_decision(self, d: Decision) -> None:
        if d.to_status not in COLORS:
            return
        now = time.monotonic()
        if now - self._last.get(d.agent_id, -MIN_GAP_S) < MIN_GAP_S and d.to_status is not AgentStatus.quarantined:
            return
        self._last[d.agent_id] = now
        fields = [{"name": "Reason", "value": d.reason[:1000], "inline": False},
                  {"name": "Decided by", "value": d.actor, "inline": True}]
        if d.details.get("revoked_tokens"):
            fields.append({"name": "Tokens revoked", "value": str(d.details["revoked_tokens"]), "inline": True})
        embed = {"title": f"ThreatLens: {d.agent_id} {TITLES[d.to_status]}", "color": COLORS[d.to_status],
                 "fields": fields, "timestamp": d.ts.isoformat()}
        if self.console_url and d.alert_id:
            embed["url"] = f"{self.console_url.rstrip('/')}/console/incidents/{d.alert_id}"
        try:
            r = await self._client.post(self.url, json={"username": "ThreatLens", "embeds": [embed]})
            if r.status_code >= 400:
                log.warning("Discord webhook returned HTTP %s", r.status_code)
        except httpx.HTTPError as e:
            log.warning("Discord webhook failed: %s", type(e).__name__)

    async def aclose(self) -> None:
        await self._client.aclose()
