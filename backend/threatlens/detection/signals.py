"""The nine behavioral signals. Each returns a SignalScore with a plain-language reason.

Every learned component returns 0 without history, so a brand-new agent can't
trigger false alarms (scenario B2). Structural parts (scope, ceiling, canary)
need no history and work from the first action.
"""

from collections import Counter
from dataclasses import dataclass

import numpy as np

from threatlens.core.schemas import ActionEvent, DecisionType, RoleContract, SignalId, SignalScore
from threatlens.gateway.catalog import ResolvedAction, in_scope
from threatlens.gateway.hooks import ScoringContext
from threatlens.scanner import url_risk

from .baselines import SESSION_BUCKETS, SESSION_FEATURES, AgentBaseline, BaselineStore, RoleBaseline, jensen_shannon
from .roles import RoleVectors

CONCURRENT_WINDOW_S = 300
TAINT_WINDOW = 10  # actions
CUSUM_KAPPA = 0.05
CUSUM_H = 1.5
MIN_COHORT = 20
MIN_HOST_HISTORY = 20


def _clip(x: float) -> float:
    return max(0.0, min(1.0, x))


def _score(signal: SignalId, value: float, evidence: str = "", **details) -> SignalScore:
    return SignalScore(signal=signal, value=round(_clip(value), 4), evidence=evidence, details=details)


@dataclass
class Inputs:
    event: ActionEvent
    ctx: ScoringContext
    agent_b: AgentBaseline
    role_b: RoleBaseline
    store: BaselineStore
    prev_token: str
    token: str
    now: float

    @property
    def a(self) -> ResolvedAction:
        return self.ctx.action

    @property
    def contract(self) -> RoleContract:
        return self.ctx.contract


def token_for(a: ResolvedAction) -> str:
    return f"{a.tool}:{a.label.resource_class}"


# ---------------------------------------------------------------- S0 runtime fingerprint


def s0_runtime(x: Inputs) -> SignalScore:
    host, sdk, jti = x.event.runtime.host or "", x.event.runtime.sdk or "", x.event.token_jti
    prev = x.agent_b.jti_hosts.get(jti)
    x.agent_b.jti_hosts[jti] = (host, x.now)
    if prev and host and prev[0] and prev[0] != host and x.now - prev[1] < CONCURRENT_WINDOW_S:
        return _score(SignalId.S0, 1.0, f"the same token is in use from {prev[0]} and {host} at the same time",
                      hosts=[prev[0], host])
    known = sum(x.agent_b.hosts.values())
    if host and known >= MIN_HOST_HISTORY and x.agent_b.hosts[host] == 0:
        return _score(SignalId.S0, 0.6, f"first time this agent runs on {host} after {known} actions elsewhere")
    if sdk and sum(x.agent_b.sdks.values()) >= MIN_HOST_HISTORY and x.agent_b.sdks[sdk] == 0:
        return _score(SignalId.S0, 0.3, f"new client software ({sdk})")
    return _score(SignalId.S0, 0.0)


# ---------------------------------------------------------------- S1 role conformance


def s1_role(x: Inputs, rv: RoleVectors, action_vec: np.ndarray, floor: float) -> SignalScore:
    a, c = x.a, x.contract
    sim, closest = rv.closest(action_vec)
    semantic = _clip((rv.t_in - sim) / max(rv.t_in - floor, 1e-6))

    reasons, structural = [], 0.0
    if a.tool not in c.allowed_tools:
        structural = 1.0
        reasons.append(f"{a.tool} isn't part of the {c.role} role")
    scope = c.resource_scopes.get(a.tool)
    out_of_scope = scope is not None and not in_scope(a.spec.kind, a.resource, scope)
    above = a.label.sensitivity.rank > c.data_sensitivity_ceiling.rank
    if out_of_scope:
        structural = max(structural, 0.8)
        reasons.append(f"{a.resource} is outside the {c.role} role's scope for {a.tool}")
    if above:
        structural = max(structural, 0.8)
        reasons.append(f"{a.label.sensitivity.value} data is above the role's {c.data_sensitivity_ceiling.value} ceiling")
    if out_of_scope and above:
        structural = max(structural, 0.9)

    if not reasons and scope is not None:
        semantic *= 0.3  # explicitly in scope: the contract already vouches for it
    value = max(structural, semantic)
    if not reasons and semantic >= 0.5:
        reasons.append(f"doesn't resemble the {c.role} role's normal work")
    evidence = "; ".join(reasons) + (f" (similarity to role {sim:.2f}, typical ≥ {rv.t_in:.2f})" if reasons else "")
    return _score(SignalId.S1, value, evidence, similarity=round(sim, 4), t_in=round(rv.t_in, 4),
                  closest=closest, structural=structural, semantic=round(semantic, 4))


# ---------------------------------------------------------------- S2 sequence surprise


def s2_sequence(x: Inputs) -> SignalScore:
    vocab = x.store.vocab(x.agent_b, x.role_b)
    r_agent, n_agent, c_agent = x.agent_b.markov.ratio(x.prev_token, x.token, vocab)
    r_role, n_role, c_role = x.role_b.markov.ratio(x.prev_token, x.token, vocab)
    lam = n_agent / (n_agent + 50)
    ratio = lam * r_agent + (1 - lam) * r_role
    n_eff = n_agent + n_role
    confidence = n_eff / (n_eff + 10)
    value = (1 - min(1.0, ratio)) * confidence
    evidence = ""
    if value >= 0.3:
        seen = c_agent + c_role
        evidence = (f"{x.prev_token} → {x.token} " + ("never seen" if seen == 0 else f"seen only {seen} time(s)")
                    + f" in {n_eff} similar transitions")
    return _score(SignalId.S2, value, evidence, ratio=round(ratio, 4), observations=n_eff)


# ---------------------------------------------------------------- S3 session profile


def session_features(x: Inputs) -> dict[str, float]:
    events = [*x.ctx.session.history, x.event]
    return {
        "distinct_tools": len({e.action.tool for e in events}),
        "distinct_classes": len({e.action.resource_class for e in events}),
        "max_sensitivity": max(e.action.sensitivity.rank for e in events),
        "external_egress": sum(1 for e in events if e.action.destination),
        "denied": sum(1 for e in events if e.decision is DecisionType.deny),
        "kb_out": sum(e.action.bytes_out for e in events) / 1000,
    }


def bucket_for(step: int) -> int | None:
    eligible = [b for b in SESSION_BUCKETS if step >= b]
    return eligible[-1] if eligible else None


def s3_session(x: Inputs, features: dict[str, float], step: int) -> SignalScore:
    bucket = bucket_for(step)
    if bucket is None:
        return _score(SignalId.S3, 0.0)
    worst, why = 0.0, ""
    for f in SESSION_FEATURES:
        st = x.role_b.stat(f, bucket)
        if st.n < MIN_COHORT:
            continue
        z = (features[f] - st.mean) / max(st.std, 0.5, 0.1 * abs(st.mean))
        if z > worst:
            worst, why = z, f"{f.replace('_', ' ')} is {features[f]:g} by action {step}; {x.contract.role} sessions average {st.mean:.1f}"
    return _score(SignalId.S3, (worst - 2) / 3, why if worst > 2 else "", z=round(worst, 2))


# ---------------------------------------------------------------- S5 sensitivity & egress


def s5_sensitivity_egress(x: Inputs) -> SignalScore:
    a, c = x.a, x.contract
    over = max(0, a.label.sensitivity.rank - c.data_sensitivity_ceiling.rank)
    sens = over / 2
    reasons, egress, tripwire = [], 0.0, False
    if over:
        reasons.append(f"reads {a.label.sensitivity.value} data ({a.label.resource_class})")
    if a.spec.egress and a.external and a.destination:
        dest = a.destination
        known = dest in c.egress_allowlist or dest in x.agent_b.destinations or dest in x.role_b.destinations
        if known:
            egress = 0.1
        else:
            risk, _ = url_risk(f"https://{dest}/")
            egress = 0.6 + 0.4 * risk
            reasons.append(f"sends data to {dest}, a destination this role has never used")
            earlier = [e for e in x.ctx.session.history
                       if e.decision in (DecisionType.allow, DecisionType.allow_logged)
                       and e.action.sensitivity.rank > c.data_sensitivity_ceiling.rank]
            if earlier:
                tripwire = True
                reasons.append(f"after reading {earlier[-1].action.resource} earlier in this session")
        if a.bytes_out > 50_000:
            egress += 0.1
    value = 1.0 if tripwire else max(sens, egress)
    return _score(SignalId.S5, value, "; ".join(reasons), tripwire="sensitive_then_egress" if tripwire else None,
                  destination=a.destination)


# ---------------------------------------------------------------- S6 delegation chain


def s6_delegation(x: Inputs, root: RoleContract | None) -> SignalScore:
    depth = x.event.delegation.depth
    if depth == 0 or root is None:
        return _score(SignalId.S6, 0.0)
    a = x.a
    if a.tool not in root.allowed_tools:
        return _score(SignalId.S6, 0.8, f"requested on behalf of the {root.role} role, which never uses {a.tool}",
                      root_role=root.role)
    scope = root.resource_scopes.get(a.tool)
    if (scope is not None and not in_scope(a.spec.kind, a.resource, scope)) or \
            a.label.sensitivity.rank > root.data_sensitivity_ceiling.rank:
        return _score(SignalId.S6, 0.6, f"{a.resource} is outside what the {root.role} role that started "
                      f"this chain may reach", root_role=root.role)
    return _score(SignalId.S6, 0.2 if depth >= 2 else 0.0, "long delegation chain" if depth >= 2 else "")


# ---------------------------------------------------------------- S4 provenance taint


def s4_provenance(x: Inputs, novelty: float) -> SignalScore:
    step = x.ctx.session.step + 1
    best, cause = 0.0, None
    for t in x.ctx.session.taints:
        ago = step - t.step
        if ago > TAINT_WINDOW or t.injection_score <= 0:
            continue
        recency = 1.0 if ago <= 3 else max(0.4, 1 - (ago - 3) * 0.1)
        if t.injection_score * recency > best:
            best, cause = t.injection_score * recency, (t, ago)
    if cause is None:
        return _score(SignalId.S4, 0.0)
    t, ago = cause
    value = best * novelty
    techniques = f", {', '.join(t.techniques)}" if t.techniques else ""
    evidence = (f"{t.source} (injection {t.injection_score:.2f}{techniques}) was read {ago} action"
                f"{'s' if ago != 1 else ''} earlier") if value >= 0.2 else ""
    return _score(SignalId.S4, value, evidence, content_id=t.content_id, injection=t.injection_score,
                  steps_ago=ago, novelty=round(novelty, 4))


# ---------------------------------------------------------------- S7 slow drift


def s7_drift(x: Inputs, s1: float) -> SignalScore:
    b = x.agent_b
    b.recent_classes.append(x.a.label.resource_class)
    if not b.anchor_frozen:
        return _score(SignalId.S7, 0.0)
    b.cusum = max(0.0, b.cusum + s1 - b.anchor_mean - CUSUM_KAPPA)
    cusum = b.cusum / CUSUM_H
    jsd = jensen_shannon(b.anchor_classes, Counter(b.recent_classes)) if len(b.recent_classes) >= 20 else 0.0
    shift = (jsd - 0.15) / 0.45
    value = max(cusum, shift)
    evidence = ""
    if value >= 0.3:
        evidence = (f"behavior has been drifting away from the role for a while (cumulative drift {b.cusum:.2f})"
                    if cusum >= shift else f"the mix of data this agent touches has shifted (divergence {jsd:.2f})")
    return _score(SignalId.S7, value, evidence, cusum=round(b.cusum, 4), jsd=round(jsd, 4))


# ---------------------------------------------------------------- S8 canary


def s8_canary(x: Inputs) -> SignalScore:
    if x.a.label.canary:
        return _score(SignalId.S8, 1.0, f"touched {x.a.resource}, a bait resource no role ever needs")
    return _score(SignalId.S8, 0.0)
