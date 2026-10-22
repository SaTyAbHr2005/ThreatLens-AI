import { useRef, useState } from 'react';
import { Link } from 'react-router';
import { countUp, deal, useGSAP } from '../../motion/gsap';
import { ago, type Signature, type Trend, useApi } from '../api';
import { DriftChart, Empty } from '../ui';

interface Summary {
  signatures: { total: number; confirmed: number; benign: number; agents_exposed: number };
  top_attacked_roles: [string, number][];
  top_techniques: [string, number][];
  top_blocked_destinations: [string, number][];
  fleet_score: number;
}

export default function Intel() {
  const summary = useApi<Summary>('/v1/intel/summary', 8000);
  const trend = useApi<Trend>('/v1/intel/trend?minutes=60', 10000);
  const sigs = useApi<Signature[]>('/v1/intel/signatures', 8000);
  const [open, setOpen] = useState<string | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const s = summary.data;
  useGSAP(() => {
    root.current?.querySelectorAll<HTMLElement>('[data-to]').forEach((el) => countUp(el, +el.dataset.to!));
  }, { dependencies: [s?.signatures.total, s?.signatures.agents_exposed], scope: root });
  useGSAP(() => deal(root.current), { dependencies: [sigs.data?.length], scope: root });

  return (
    <div ref={root} className="page intel">
      <section className="tiles">
        {[
          ['Injection signatures', s?.signatures.total],
          ['Confirmed attacks', s?.signatures.confirmed],
          ['Agents exposed', s?.signatures.agents_exposed],
          ['Fleet threat score', s ? Math.round(s.fleet_score) : undefined],
        ].map(([label, v]) => (
          <div key={label as string} className="tile">
            <span className="num tile-v" data-to={v ?? 0}>{v ?? '–'}</span>
            <span className="muted">{label}</span>
          </div>
        ))}
      </section>
      <section className="panel">
        <h2>Fleet drift, last hour</h2>
        {trend.data && <DriftChart trend={trend.data} />}
      </section>
      <section className="intel-tops">
        {([['Most-attacked roles', s?.top_attacked_roles], ['Top hiding techniques', s?.top_techniques], ['Top blocked destinations', s?.top_blocked_destinations]] as const).map(([t, rows]) => (
          <div key={t} className="panel">
            <h3>{t}</h3>
            {rows?.length ? <ol className="bars">{rows.map(([k, n]) => (
              <li key={k}><span className="mrz">{k.replace(/_/g, ' ')}</span><span className="bar"><i style={{ width: `${(n / rows[0][1]) * 100}%` }} /></span><span className="num">{n}</span></li>
            ))}</ol> : <p className="muted small">Nothing yet.</p>}
          </div>
        ))}
      </section>
      <section>
        <h2>Injection signature feed</h2>
        <p className="muted">Every hidden instruction the fleet has read, fingerprinted. A near-duplicate read by any other agent is caught on sight: fleet immunity.</p>
        {sigs.data && !sigs.data.length && <Empty>No signatures yet. Run A1 or the Red Team Studio from <Link to="/console/simulate">Simulate</Link>.</Empty>}
        <ul className="rows">
          {sigs.data?.map((g) => (
            <li key={g.id} data-deal>
              <button className="row-link sig" aria-expanded={open === g.id} onClick={() => setOpen(open === g.id ? null : g.id)}>
                <span className="row-head mrz">{g.instruction}</span>
                <span className="muted">{g.techniques.join(', ').replace(/_/g, ' ')} · {g.hits} hits · {g.status} · last {ago(g.last_seen)}</span>
              </button>
              {open === g.id && (
                <div className="sig-detail">
                  <p>Read by {g.agents.length} agent{g.agents.length === 1 ? '' : 's'}:</p>
                  <ul>{g.agents.map((a) => <li key={a}><Link to={`/console/agents?id=${a}`}>{a}</Link></li>)}</ul>
                  <p className="muted small">First seen in {g.first_source}. Simhash <span className="mrz">{g.simhash}</span></p>
                </div>
              )}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
