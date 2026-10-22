import { useRef } from 'react';
import { Link } from 'react-router';
import { deal, useGSAP } from '../../motion/gsap';
import { AgentPassport } from '../../passport/AgentPassport';
import { type Agent, type Alert, statusLabel, type Trend, useApi } from '../api';
import { DriftChart, Empty, Feed, identityOf, Risk, sealOf } from '../ui';
import { useLive } from '../live';

export default function Overview() {
  const live = useLive();
  const agents = useApi<Agent[]>('/v1/agents', 4000);
  const alerts = useApi<Alert[]>('/v1/alerts?status=open&limit=20', 4000);
  const trend = useApi<Trend>('/v1/intel/trend?minutes=30', 10000);
  const root = useRef<HTMLDivElement>(null);
  useGSAP(() => deal(root.current), { dependencies: [agents.data?.length, alerts.data?.length], scope: root });

  const latest = (id: string) => live.events.find((e) => e.agent_id === id);
  return (
    <div ref={root} className="page overview">
      <section className="area-agents">
        <h2>Agents</h2>
        {agents.data && !agents.data.length && <Empty>No agents yet. Run the PDF attack from <Link to="/console/simulate">Simulate</Link> to see one.</Empty>}
        <div className="mini-grid">
          {agents.data?.map((a) => (
            <Link key={a.agent_id} to={`/console/agents?id=${a.agent_id}`} className="mini" data-deal>
              <AgentPassport flat identity={identityOf(a)} {...sealOf(a, latest(a.agent_id)?.scores)} />
              <span className="mini-meta">
                <span>{a.role}</span>
                <span className={`tag tag-${a.status}`}>{statusLabel[a.status]}</span>
              </span>
            </Link>
          ))}
        </div>
      </section>

      <section className="area-chart panel">
        <h2>Drift, last 30 minutes</h2>
        {trend.data ? <DriftChart trend={trend.data} /> : <div className="chart-skeleton" />}
      </section>

      <section className="area-feed panel">
        <h2>Live actions</h2>
        <Feed events={live.events.slice(0, 40)} />
      </section>

      <section className="area-incidents">
        <h2>Open incidents</h2>
        {alerts.data && !alerts.data.length && <Empty>No incidents. Run the PDF attack from <Link to="/console/simulate">Simulate</Link> to see one.</Empty>}
        <ul className="rows">
          {alerts.data?.map((a) => (
            <li key={a.id} data-deal>
              <Link to={`/console/incidents/${a.id}`} className="row-link">
                <span className="row-head">{a.headline}</span>
                <Risk value={a.risk} />
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
