import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { AgentPassport } from '../../passport/AgentPassport';
import { SIGNALS } from '../../passport/rosette';
import { type Agent, type Alert, decisionLabel, type Replay as ReplayData, useApi } from '../api';
import { useLive } from '../live';
import { Empty, ErrorNote, Risk } from '../ui';

export default function Replay() {
  const { session } = useParams();
  const nav = useNavigate();
  const live = useLive();
  const alerts = useApi<Alert[]>('/v1/alerts?limit=50');
  const agents = useApi<Agent[]>('/v1/agents');
  const rep = useApi<ReplayData>(session ? `/v1/replay/${session}` : null);
  const [i, setI] = useState(0);

  const sessions = [...new Map([
    ...(alerts.data ?? []).map((a) => [a.session_id, `${a.agent_id} · incident`] as const),
    ...live.events.map((e) => [e.session_id, e.agent_id] as const),
  ]).entries()].slice(0, 40);

  const steps = rep.data?.steps ?? [];
  useEffect(() => setI(Math.max(0, steps.length - 1)), [steps.length]);
  const step = steps[i];
  const agent = agents.data?.find((a) => a.agent_id === step?.agent_id);
  // The drift the agent had at this point: the running maximum risk so far, the way the gateway raises it.
  const drift = steps.slice(0, i + 1).reduce((m, s) => Math.max(m, s.risk ?? 0), 0) / 100;
  const until = steps[i + 1]?.ts ?? '9999';
  const contained = rep.data?.decisions.some((d) => d.ts < until && d.to_status && d.to_status !== 'active');

  return (
    <div className="page replay">
      <section className="replay-pick">
        <h2>Replay</h2>
        <label>Session
          <select value={session ?? ''} onChange={(e) => nav(`/console/replay/${e.target.value}`)}>
            <option value="" disabled>Pick a session</option>
            {session && !sessions.some(([s]) => s === session) && <option value={session}>{session}</option>}
            {sessions.map(([s, label]) => <option key={s} value={s}>{label} · {s.slice(-8)}</option>)}
          </select>
        </label>
        {!sessions.length && !session && <Empty>No sessions yet. Run a scenario from <Link to="/console/simulate">Simulate</Link>, then rewind it here.</Empty>}
        <ErrorNote error={rep.error} />
      </section>

      {step && (
        <>
          <section className="replay-stage">
            {agent && (
              <AgentPassport className="passport-3d" identity={{ name: agent.agent_id, role: agent.role, roleVersion: agent.role_version, owner: agent.owner, status: contained ? 'step_up' : 'active' }}
                drift={drift} clamp={contained ? 1 : 0}
                signals={SIGNALS.map((s) => Math.max(0, Math.min(1, ((step.scores[s.id] ?? 0) - 0.4) / 0.4)))} />
            )}
            <div className="scrub">
              <input type="range" min={0} max={steps.length - 1} value={i} onChange={(e) => setI(+e.target.value)}
                aria-label="Step in the session" aria-valuetext={`Step ${i + 1} of ${steps.length}: ${step.action.tool}`} />
              <ol className="scrub-ticks" aria-hidden>
                {steps.map((s, k) => <li key={s.id} className={`tick d-${s.decision ?? 'none'}${k === i ? ' on' : ''}`} onClick={() => setI(k)} />)}
              </ol>
            </div>
          </section>
          <section className="panel replay-step">
            <p className="muted">Step {i + 1} of {steps.length} · {new Date(step.ts).toLocaleTimeString()}</p>
            <p className="mrz call-dark">{step.action.tool} {step.action.resource ?? step.action.destination ?? ''}</p>
            <p><b>{decisionLabel[step.decision ?? ''] ?? '–'}</b> · risk <Risk value={step.risk} /></p>
            {step.reason && <p className="muted">{step.reason}</p>}
            <ul className="score-bars">
              {SIGNALS.map((s) => {
                const v = step.scores[s.id] ?? 0;
                return (
                  <li key={s.id}>
                    <span>{s.name}</span>
                    <span className="bar"><i style={{ width: `${v * 100}%`, transition: 'width 200ms var(--ease-ui)' }} className={v > 0.6 ? 'hot' : ''} /></span>
                    <span className="num">{v.toFixed(2)}</span>
                  </li>
                );
              })}
            </ul>
            {!!step.provenance.tainted_by.length && (
              <p className="callout">Read after untrusted content: {rep.data!.content.filter((c) => step.provenance.tainted_by.includes(c.id)).map((c) => c.source).join(', ')}</p>
            )}
          </section>
        </>
      )}
    </div>
  );
}
