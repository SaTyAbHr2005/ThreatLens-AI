"""Build the explanation for an alert: deterministic, from the signals alone.

Every alert answers: what happened, why it scored this risk (additive factors with
evidence), what caused it (the content item behind S4: causal drift attribution),
what the risk would be without that cause (counterfactual), which known threat
patterns it matches, and what to do next.
"""

from collections import OrderedDict

from threatlens.core.schemas import (
    SIGNAL_NAMES,
    ActionEvent,
    Alert,
    ContentItem,
    Factor,
    SignalId,
    SignalScore,
    Tier,
)
from threatlens.gateway.hooks import ScoringContext

from .model import INTERACTION, Fused, Weights, fuse, tier_for_risk, without

MIN_FACTOR_SHARE = 0.03


class ContentCache:
    """Recently scanned content items by id (bus subscriber), for decoded injections."""

    def __init__(self, size: int = 2000):
        self._items: OrderedDict[str, ContentItem] = OrderedDict()
        self._size = size

    async def add(self, item: ContentItem) -> None:
        self._items[item.id] = item
        while len(self._items) > self._size:
            self._items.popitem(last=False)

    def get(self, content_id: str | None) -> ContentItem | None:
        return self._items.get(content_id) if content_id else None


def factors(signals: list[SignalScore], fused: Fused) -> list[Factor]:
    """Additive shares of the risk, strongest first. The S1·S4 interaction is credited to S4:
    it is the 'acted on the hidden instruction' part of provenance."""
    by_id = {s.signal.value: s for s in signals}
    share: dict[str, float] = {}
    for k, v in fused.contributions.items():
        key = "S4" if k == INTERACTION else k
        share[key] = share.get(key, 0.0) + max(v, 0.0)
    total = sum(share.values()) or 1.0
    out = []
    for k, v in sorted(share.items(), key=lambda kv: -kv[1]):
        sig = by_id.get(k)
        if sig is None or v / total < MIN_FACTOR_SHARE or not sig.evidence:
            continue
        out.append(Factor(signal=SignalId(k), contribution=round(v / total, 3),
                          evidence=f"{SIGNAL_NAMES[SignalId(k)]}: {sig.evidence}"))
    return out


def frameworks(signals: list[SignalScore]) -> list[str]:
    v = {s.signal.value: s for s in signals}
    out = []
    if v.get("S4") and v["S4"].value >= 0.3:
        out += ["OWASP LLM01:2025 Prompt Injection", "MITRE ATLAS AML.T0051 LLM Prompt Injection"]
    if any(v.get(k) and v[k].value >= 0.5 for k in ("S1", "S6")):
        out.append("OWASP LLM06:2025 Excessive Agency")
    if v.get("S5") and v["S5"].value >= 0.5:
        out.append("OWASP LLM02:2025 Sensitive Information Disclosure")
    if v.get("S0") and v["S0"].value >= 0.6:
        out.append("MITRE ATT&CK T1550.001 Application Access Token")
    if v.get("S8") and v["S8"].value >= 1.0:
        out.append("Deception: honeytoken (canary) accessed")
    return out


def recommendations(signals: list[SignalScore], event: ActionEvent, cause: ContentItem | None) -> list[str]:
    v = {s.signal.value: s for s in signals if s.value >= 0.3}
    recs = []
    if "S8" in v:
        recs.append("Treat this as a confirmed compromise: rotate the agent's credentials and review the whole session.")
    if "S4" in v:
        src = cause.source if cause else "the untrusted content it read"
        recs.append(f"Quarantine {src} and check where it came from.")
        recs.append("Check which other agents read the same content (Threat Intel → known signatures).")
    if "S5" in v and event.action.destination:
        recs.append(f"Block {event.action.destination} at the egress proxy.")
    elif "S5" in v or "S1" in v:
        recs.append(f"Review whether {event.agent_id} should be able to reach {event.action.resource} at all.")
    if "S0" in v:
        host = event.runtime.host or "the unknown host"
        recs.append(f"Rotate {event.agent_id}'s token and investigate {host}.")
    if "S6" in v:
        recs.append(f"Review the delegation chain {' → '.join(event.delegation.chain)}.")
    if "S7" in v:
        recs.append("Compare recent behavior with the Role Contract; if it's a legitimate change, approve it as an amendment.")
    if not recs:
        recs.append("Review this session's actions.")
    return list(dict.fromkeys(recs))


def headline(ctx: ScoringContext, event: ActionEvent, signals: list[SignalScore], fused: Fused) -> str:
    """Template headline (always available). An LLM narrative may replace it later."""
    v = {s.signal.value: s for s in signals}
    who = f"The {ctx.contract.role} agent ({event.agent_id})"
    what = f"{event.action.tool} on {event.action.resource or 'an unknown resource'}"
    lead = next((s for s in sorted(signals, key=lambda s: -s.value) if s.evidence and s.signal.value != "S4"), None)
    text = f"{who} ran {what}"
    if lead:
        text += f": {lead.evidence}"
    if v.get("S4") and v["S4"].value >= 0.3 and v["S4"].evidence:
        text += f". It happened right after untrusted content: {v['S4'].evidence}"
    return text.rstrip(".") + "."


def counterfactual(signals: list[SignalScore], fused: Fused, w: Weights, cause: ContentItem | None) -> str | None:
    if not cause:
        return None
    alt = fuse(without(signals, "S4"), w)
    if fused.risk - alt.risk < 10:
        return None
    return (f"Without {cause.source}, this action would score {alt.risk:.0f} "
            f"({tier_for_risk(alt.risk).value.replace('_', '-')}) instead of {fused.risk:.0f}.")


def build_alert(ctx: ScoringContext, event: ActionEvent, signals: list[SignalScore], fused: Fused,
                w: Weights, content: ContentCache) -> Alert:
    s4 = next((s for s in signals if s.signal is SignalId.S4), None)
    cause_id = s4.details.get("content_id") if s4 and s4.value >= 0.3 else None
    cause = content.get(cause_id)
    return Alert(
        agent_id=event.agent_id,
        session_id=event.session_id,
        event_id=event.id,
        risk=fused.risk,
        tier=fused.tier if fused.tier is not Tier.allow else Tier.monitor,
        headline=headline(ctx, event, signals, fused),
        factors=factors(signals, fused),
        cause_content_id=cause_id,
        decoded_injection=(cause.decoded_text[:500] or None) if cause else None,
        counterfactual=counterfactual(signals, fused, w, cause),
        timeline=[e.id for e in list(ctx.session.history)[-9:]] + [event.id],
        frameworks=frameworks(signals),
        recommendations=recommendations(signals, event, cause),
        scores={s.signal: s.value for s in signals},
        floor=fused.floor,
    )
