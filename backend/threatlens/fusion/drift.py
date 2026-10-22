"""Per-agent Drift Score (0–100): what the dashboard shows and what containment acts on.

    drift = max( EWMA(risk),            smooth trend
                 peak · decay,          a spike stays visible, then fades with clean actions
                 S7 · 85 )              slow drift that no single action reveals
    trust = 100 − drift
"""

from dataclasses import dataclass

EWMA_ALPHA = 0.3
PEAK_DECAY = 0.95  # per subsequent action
S7_SCALE = 85.0


@dataclass
class DriftState:
    ewma: float = 0.0
    peak: float = 0.0
    value: float = 0.0


class DriftTracker:
    def __init__(self) -> None:
        self._agents: dict[str, DriftState] = {}

    def update(self, agent_id: str, risk: float, s7: float = 0.0) -> float:
        st = self._agents.setdefault(agent_id, DriftState())
        st.ewma = EWMA_ALPHA * risk + (1 - EWMA_ALPHA) * st.ewma
        st.peak = max(risk, st.peak * PEAK_DECAY)
        st.value = round(min(100.0, max(st.ewma, st.peak, s7 * S7_SCALE)), 2)
        return st.value

    def get(self, agent_id: str) -> float:
        st = self._agents.get(agent_id)
        return st.value if st else 0.0

    def reset(self, agent_id: str) -> None:
        """Analyst released the agent or marked the alert harmless (M6)."""
        self._agents.pop(agent_id, None)
