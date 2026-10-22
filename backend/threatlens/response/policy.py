"""When to contain, when to isolate, when to relax. Pure functions, no I/O.

Contain first, isolate only on certainty or persistence:
- risk or drift ≥ 60 → Restrict (snap back to the Role Contract)
- risk or drift ≥ 75 → Step-up (sensitive data and external sends need a person's approval)
- Isolate (tokens revoked, agent paused) only when:
    · a canary was touched, or the same token is in use from two machines (near-certain), or
    · the agent keeps attacking while already contained (ISOLATE_STRIKES high-risk actions)
So a hijacked agent loses its out-of-role reach at once, but keeps doing its job (pillar 3).

Relaxing is gradual and only automatic below Isolate: after RELAX_STREAK clean actions in a
row, Step-up → Restrict (drift < 60), then Restrict → normal (drift < 40). Isolation always
needs a person.
"""

from threatlens.core.schemas import AgentStatus

ISOLATE_STRIKES = 3
STRIKE_RISK = 75.0
RELAX_STREAK = 10
CERTAIN_FLOORS = {"canary", "token_in_two_places"}

LEVEL = [AgentStatus.active, AgentStatus.restricted, AgentStatus.step_up, AgentStatus.quarantined]


def level(status: AgentStatus) -> int:
    return LEVEL.index(status)


def escalation(current: AgentStatus, risk: float, drift: float, tripwires, strikes: int) -> AgentStatus:
    """The status this agent should have now. Never lower than `current` (relaxing is separate).
    `tripwires` lists every tripwire that fired, whether or not it set the risk floor."""
    if current is AgentStatus.quarantined:
        return current
    if CERTAIN_FLOORS & set(tripwires or ()) or strikes >= ISOLATE_STRIKES:
        return AgentStatus.quarantined
    signal = max(risk, drift)
    target = AgentStatus.step_up if signal >= 75 else AgentStatus.restricted if signal >= 60 else AgentStatus.active
    return target if level(target) > level(current) else current


def is_strike(status_before: AgentStatus, risk: float) -> bool:
    """A high-risk action by an agent that was already contained."""
    return status_before in (AgentStatus.restricted, AgentStatus.step_up) and risk >= STRIKE_RISK


def relaxation(current: AgentStatus, drift: float, clean_streak: int) -> AgentStatus:
    if clean_streak < RELAX_STREAK:
        return current
    if current is AgentStatus.step_up and drift < 60:
        return AgentStatus.restricted
    if current is AgentStatus.restricted and drift < 40:
        return AgentStatus.active
    return current
