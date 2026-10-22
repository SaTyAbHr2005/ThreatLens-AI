import { useRef } from 'react';
import { Link, useSearchParams } from 'react-router';
import { deal, useGSAP } from '../../motion/gsap';
import { AgentPassport } from '../../passport/AgentPassport';
import { type Agent, type AgentRisk, ago, type Alert, type Decision, type RoleDetail, statusLabel, useApi } from '../api';
import { useLive } from '../live';
import { Empty, identityOf, Risk, sealOf } from '../ui';

export default function Agents() {
  const [params, setParams] = useSearchParams();
  const agents = useApi<Agent[]>('/v1/agents', 4000);
  const id = params.get('id') ?? agents.data?.[0]?.agent_id ?? null;
  const agent = agents.data?.find((a) => a.agent_id === id);
  return (
    <div className="page agents">
      <section className="agent-picker">
        <h2>Agents</h2>
        {agents.data && !agents.data.length && <Empty>No agents yet. Run a scenario from <Link to="/console/simulate">Simulate</Link>.</Empty>}
        <ul className="rows">
          {agents.data?.map((a) => (
            <li key={a.agent_id}>
              <button className={a.agent_id === id ? 'row-link sel' : 'row-link'} onClick={() => setParams({ id: a.agent_id })}>
                <span className="row-head">{a.agent_id}</span>
                <span className={`tag tag-${a.status}`}>{statusLabel[a.status ?? 'active']}</span>
                <Risk value={a.drift} />
              </button>
            </li>
          ))}
        </ul>
      </section>
      {agent && <AgentDetail key={agent.agent_id} agent={agent} />}
    </div>
  );
}

function AgentDetail({ agent }: { agent: Agent }) {
  const live = useLive();
  const role = useApi<RoleDetail>(`/v1/roles/${agent.role}`);
  const risk = useApi<AgentRisk>(`/v1/agents/${agent.agent_id}/risk`, 4000);
  const decisions = useApi<Decision[]>(`/v1/decisions?agent_id=${agent.agent_id}&limit=20`, 6000);
  const alerts = useApi<Alert[]>(`/v1/alerts?agent_id=${agent.agent_id}&limit=5`, 6000);
  const root = useRef<HTMLDivElement>(null);
  useGSAP(() => deal(root.current), { dependencies: [decisions.data?.length, role.data ? 1 : 0], scope: root });

  const latest = live.events.find((e) => e.agent_id === agent.agent_id);
  const observed = new Map<string, Set<string>>();
  live.events.filter((e) => e.agent_id === agent.agent_id).forEach((e) => {
    const s = observed.get(e.action.tool) ?? new Set();
    s.add(e.action.resource ?? e.action.destination ?? '·');
    observed.set(e.action.tool, s);
  });
  const c = role.data?.contract;
  const scope = (tool: string) => {
    const v = c?.resource_scopes?.[tool];
    return Array.isArray(v) ? v.join(', ') : v ? JSON.stringify(v) : 'any resource';
  };
  const recent = risk.data?.recent ?? [];
  const max = Math.max(1, recent.length - 1);
  const spark = recent.map((p, i) => `${i ? 'L' : 'M'}${((i / max) * 300).toFixed(1)} ${(60 - ((p.risk ?? 0) / 100) * 60).toFixed(1)}`).join('');

  return (
    <div ref={root} className="agent-detail">
      <div className="agent-hero">
        <AgentPassport className="passport-3d" identity={identityOf(agent)} {...sealOf(agent, latest?.scores)} />
        <dl className="agent-facts">
          <div><dt>Status</dt><dd className={`tag tag-${agent.status}`}>{statusLabel[agent.status ?? 'active']}</dd></div>
          <div><dt>Drift</dt><dd className="num">{(agent.drift ?? 0).toFixed(1)} of 100</dd></div>
          <div><dt>Trust</dt><dd className="num">{risk.data ? risk.data.trust.toFixed(1) : '–'}</dd></div>
          <div><dt>Open alerts</dt><dd className="num">{risk.data?.open_alerts ?? '–'}</dd></div>
          <div className="wide">
            <dt>Risk per action, this session</dt>
            <dd>
              <svg viewBox="0 -2 300 64" className="spark" aria-label="Risk per recent action">
                <line x1={0} x2={300} y1={24} y2={24} className="th th-restrict" />
                <path d={spark} />
              </svg>
            </dd>
          </div>
        </dl>
      </div>

      <section className="panel">
        <h2>Declared and actual</h2>
        <p className="muted">The Role Contract (v{c?.version ?? '–'}) next to what this agent has done since the console opened.</p>
        <table className="table">
          <thead><tr><th>Tool</th><th>Declared scope</th><th>Observed</th></tr></thead>
          <tbody>
            {[...new Set([...(c?.allowed_tools ?? []), ...observed.keys()])].map((tool) => {
              const outside = !c?.allowed_tools.includes(tool);
              return (
                <tr key={tool} data-deal className={outside ? 'outside' : ''}>
                  <td className="mrz">{tool}</td>
                  <td>{outside ? <span className="void-text">Not in the role</span> : scope(tool)}</td>
                  <td className="mrz">{[...(observed.get(tool) ?? [])].join(', ') || <span className="muted">–</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {c && <p className="muted small">Ceiling: {c.data_sensitivity_ceiling} data · egress to {c.egress_allowlist.join(', ') || 'nowhere outside'} · {c.enforcement_mode} mode</p>}
        {alerts.data?.[0] && (
          <p className="callout">
            Latest incident: <Link to={`/console/incidents/${alerts.data[0].id}`}>{alerts.data[0].headline}</Link>. If this was legitimate new work,
            open it and choose <b>Approve this change</b> to turn it into a signed amendment.
          </p>
        )}
      </section>

      <section className="panel">
        <h2>Containment history</h2>
        {decisions.data && !decisions.data.length && <Empty>No containment changes. The agent has stayed in its role.</Empty>}
        <ol className="rows">
          {decisions.data?.map((d) => (
            <li key={d.id} data-deal className="history-row">
              <span>{d.from_status ? statusLabel[d.from_status] : '–'} → <b>{d.to_status ? statusLabel[d.to_status] : d.decision}</b></span>
              <span className="muted">{d.reason}</span>
              <span className="muted">{d.actor} · {ago(d.ts)}</span>
            </li>
          ))}
        </ol>
        {!!role.data?.amendments.length && (
          <>
            <h3>Signed amendments</h3>
            <ul>{role.data.amendments.map((m) => <li key={m.id}>v{m.from_version} → v{m.to_version}: {m.reason} <span className="muted">({m.signer})</span></li>)}</ul>
          </>
        )}
      </section>
    </div>
  );
}
