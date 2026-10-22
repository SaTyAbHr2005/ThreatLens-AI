"""Drives scenarios against the real gateway in-process.

Each run uses run-scoped agents (`<role>-agent-<run>`), so every run starts from a
clean state and can be repeated. Steps go through the same gateway path a real agent
uses, so the decisions, alerts and containment are the real ones.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

from threatlens.core.schemas import Alert, RuntimeFingerprint
from threatlens.identity import AgentToken

GRANTS = {
    # Credentials are broader than the Role Contract (as in real deployments): logistics_api.track
    # is granted but not in the contract, so B1's amendment makes it in-role without new credentials.
    "procurement": {t: ["**"] for t in
                    ("supplier_db.query", "files.read", "erp.create_pr", "email.send", "web.fetch",
                     "http.post", "logistics_api.track")},
    "support": {t: ["**"] for t in ("tickets.read", "tickets.update", "kb.search", "email.send", "http.post")},
    "hr": {t: ["**"] for t in ("hr_db.query", "hr_db.update", "files.read", "email.send")},
    "finance": {t: ["**"] for t in ("erp.read_invoice", "erp.read_pr", "ledger.query", "files.read", "email.send")},
}


@dataclass
class StepResult:
    label: str
    kind: str  # read | call | amend | delegate | note
    detail: str
    decision: str | None = None
    risk: float | None = None
    status_after: str | None = None


@dataclass
class ScenarioResult:
    scenario_id: str
    name: str
    challenge: str
    mode: str = "replay"
    steps: list[StepResult] = field(default_factory=list)
    primary_agent: str | None = None
    alert: Alert | None = None
    exfil_bytes: int = 0
    passed: bool = False
    checks: list[str] = field(default_factory=list)


class ScenarioRunner:
    def __init__(self, registry, gateway, fusion, sink, llm=None):
        self.registry = registry
        self.gateway = gateway
        self.fusion = fusion
        self.sink = sink
        self.llm = llm

    def new_run(self, scenario_id: str, name: str, challenge: str, mode: str = "replay") -> "RunContext":
        return RunContext(self, ScenarioResult(scenario_id=scenario_id, name=name, challenge=challenge, mode=mode))


class RunContext:
    def __init__(self, runner: ScenarioRunner, result: ScenarioResult):
        self.r = runner
        self.result = result
        self.run_id = uuid.uuid4().hex[:6]
        self.session = f"sc-{self.run_id}"
        self.tokens: dict[str, str] = {}  # agent_id -> token
        self._exfil_start = runner.sink.total_bytes

    async def agent(self, role: str, suffix: str = "") -> str:
        agent_id = f"{role}-agent-{self.run_id}{('-' + suffix) if suffix else ''}"
        await self.r.registry.create_agent(agent_id, role, f"{role}-team@corp.example", GRANTS.get(role))
        self.tokens[agent_id] = self.r.registry.issue_token(agent_id).token
        if self.result.primary_agent is None:
            self.result.primary_agent = agent_id
        return agent_id

    async def ensure_agent(self, agent_id: str, role: str) -> str:
        """Create the agent, or reuse and reset it (for a delegate whose name a contract pins down)."""
        from threatlens.core.schemas import AgentStatus
        from threatlens.identity import AgentExists
        try:
            await self.r.registry.create_agent(agent_id, role, f"{role}-team@corp.example", GRANTS.get(role))
        except AgentExists:
            await self.r.registry.set_status(agent_id, AgentStatus.active, drift=0.0)
        self.tokens[agent_id] = self.r.registry.issue_token(agent_id).token
        return agent_id

    def _token(self, agent_id: str) -> str:
        return self.tokens[agent_id]

    async def read(self, agent_id: str, source: str, text: str = "", carrier: str = "text",
                   raw: bytes | None = None, label: str = "") -> None:
        import base64 as _b64
        item = await self.r.gateway.register_content(self._token(agent_id), self.session, source, carrier, text, raw)
        self.result.steps.append(StepResult(
            label=label or f"{agent_id} reads {source}", kind="read",
            detail=f"injection {item.injection_score:.2f}" + (f" ({', '.join(item.techniques)})" if item.techniques else "")))

    async def call(self, agent_id: str, tool: str, label: str = "", host: str = "worker-1", **args) -> StepResult:
        from threatlens.core.security import InvalidToken

        detail = f"{tool} {args.get('path') or args.get('url') or args.get('to') or ''}".strip()
        try:
            res = await self.r.gateway.tool_call(self._token(agent_id), self.session, tool, args,
                                                 RuntimeFingerprint(host=host, sdk="sim"))
            decision, risk = res.decision.value, res.risk
        except InvalidToken:
            # The agent was isolated earlier in the run: its token is revoked, so the tool never runs.
            decision, risk = "quarantine", None
        sr = StepResult(label=label or f"{agent_id}: {tool}", kind="call", detail=detail,
                        decision=decision, risk=risk, status_after=self.r.registry.agent(agent_id).status.value)
        self.result.steps.append(sr)
        return sr

    async def delegate(self, caller_id: str, callee_role: str) -> str:
        # The caller's contract names its delegate by canonical id (e.g. "finance-agent").
        callee_id = await self.ensure_agent(f"{callee_role}-agent", callee_role)
        caller_claims: AgentToken = self.r.registry.verify(self._token(caller_id))
        issued = self.r.registry.delegate(caller_claims, callee_id)
        self.tokens[callee_id] = issued.token
        self.result.steps.append(StepResult(label=f"{caller_id} delegates to {callee_id}", kind="delegate",
                                            detail=f"effective tools: {', '.join(issued.claims.scopes) or 'none'}"))
        return callee_id

    def reissue_from_host(self, agent_id: str) -> None:
        """A fresh token for the same agent (used to simulate a token presented from another host)."""
        self.tokens[agent_id] = self.r.registry.issue_token(agent_id).token

    async def amend(self, role: str, changes: dict[str, Any], reason: str, signer: str) -> None:
        amd = await self.r.registry.amend(role, changes, reason, signer)
        for agent_id in list(self.tokens):
            if self.r.registry.agent(agent_id).role == role:
                self.tokens[agent_id] = self.r.registry.issue_token(agent_id).token  # pick up the new version
        self.result.steps.append(StepResult(label=f"signed amendment to {role} v{amd.to_version}", kind="amend",
                                            detail=f"{reason} ({signer})"))

    def note(self, text: str) -> None:
        self.result.steps.append(StepResult(label=text, kind="note", detail=""))

    def finish(self, checks: list[tuple[str, bool]]) -> ScenarioResult:
        self.result.exfil_bytes = self.r.sink.total_bytes - self._exfil_start
        if self.result.primary_agent:
            self.result.alert = self.r.fusion.open_alert(self.result.primary_agent, self.session)
        self.result.checks = [f"{'PASS' if ok else 'FAIL'}: {desc}" for desc, ok in checks]
        self.result.passed = all(ok for _, ok in checks)
        return self.result
