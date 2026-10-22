import { type ReactNode, useEffect, useRef } from 'react';
import { drawIn, gsap, reduced, stamp, useGSAP } from '../motion/gsap';
import type { Identity, SealState } from '../passport/rosette';
import { SIGNALS } from '../passport/rosette';
import { type ActionEvent, type Agent, ago, decisionLabel, type Factor, type Trend } from './api';

export const identityOf = (a: Agent): Identity => ({
  name: a.agent_id, role: a.role, roleVersion: a.role_version, owner: a.owner, status: a.status ?? 'active', issued: a.created_at,
});

export function sealOf(a: Agent, scores?: Record<string, number> | null): SealState {
  return {
    drift: (a.drift ?? 0) / 100,
    signals: SIGNALS.map((s) => Math.max(0, Math.min(1, ((scores?.[s.id] ?? 0) - 0.4) / 0.4))),
    clamp: a.status && a.status !== 'active' ? 1 : 0,
  };
}

export const tierOf = (risk: number) => (risk >= 90 ? 'isolate' : risk >= 75 ? 'step_up' : risk >= 60 ? 'restrict' : risk >= 40 ? 'monitor' : 'allow');

export function Risk({ value }: { value: number | null | undefined }) {
  if (value == null) return <span className="risk muted">–</span>;
  return <span className={`risk risk-${tierOf(value)} num`} title={`Risk ${value.toFixed(1)} of 100`}>{Math.round(value)}</span>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function ErrorNote({ error }: { error: Error | null }) {
  return error ? <p className="error-note" role="alert">{error.message}</p> : null;
}

/** Live actions: each new row arrives with a flash in its decision's color. */
export function Feed({ events, compact }: { events: ActionEvent[]; compact?: boolean }) {
  const ref = useRef<HTMLOListElement>(null);
  useGSAP(() => {
    const first = ref.current?.firstElementChild;
    if (!first || reduced()) return;
    gsap.fromTo(first, { opacity: 0, y: -14, backgroundColor: 'rgba(185,199,232,0.22)' },
      { opacity: 1, y: 0, backgroundColor: 'rgba(185,199,232,0)', duration: 0.6, ease: 'power3.out' });
  }, { dependencies: [events[0]?.id], scope: ref });
  if (!events.length) return <Empty>Waiting for agent actions. They appear here as the gateway scores them.</Empty>;
  return (
    <ol ref={ref} className={compact ? 'feed compact' : 'feed'}>
      {events.map((e) => (
        <li key={e.id} className={`feed-${e.decision ?? 'none'}`}>
          <span className="mrz feed-call">{e.action.tool} {e.action.resource ?? e.action.destination ?? ''}</span>
          <span className="feed-agent">{e.agent_id}</span>
          <span className="feed-dec">{e.shadow ? 'Shadow' : decisionLabel[e.decision ?? ''] ?? '–'}</span>
          <Risk value={e.risk} />
          {!compact && <time className="muted">{ago(e.ts)}</time>}
        </li>
      ))}
    </ol>
  );
}

/** Factor bars: each bar is labelled with its signal and its evidence (DESIGN.md §6). */
export function Factors({ factors }: { factors: Factor[] }) {
  const ref = useRef<HTMLUListElement>(null);
  const max = Math.max(0.01, ...factors.map((f) => f.contribution));
  useGSAP(() => {
    if (!reduced()) gsap.from('.bar i', { scaleX: 0, transformOrigin: 'left', duration: 0.7, ease: 'expo.out', stagger: 0.08 });
  }, { dependencies: [factors.length], scope: ref });
  return (
    <ul ref={ref} className="factors">
      {factors.map((f) => (
        <li key={f.signal + f.evidence}>
          <span className="factor-name">{SIGNALS.find((s) => s.id === f.signal)?.name ?? f.signal} <span className="muted mrz">{f.signal}</span></span>
          <span className="bar"><i style={{ width: `${(f.contribution / max) * 100}%` }} /></span>
          <span className="num factor-share">{Math.round(f.contribution * 100)}%</span>
          <p className="factor-evidence">{f.evidence}</p>
        </li>
      ))}
    </ul>
  );
}

/** A rubber stamp that lands when it first appears. */
export function Stamp({ text, sub, tone = 'void' }: { text: string; sub?: string; tone?: 'void' | 'ink' }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => stamp(ref.current), []);
  return (
    <div ref={ref} className={`doc-stamp stamp-${tone}`} role="status">
      {text}
      {sub && <small>{sub}</small>}
    </div>
  );
}

const W = 640;
const H = 200;

export function DriftChart({ trend }: { trend: Trend }) {
  const ref = useRef<SVGSVGElement>(null);
  const series = Object.entries(trend.agents);
  const n = trend.fleet.length;
  const x = (i: number) => (i / Math.max(1, n - 1)) * W;
  const y = (v: number) => H - (v / 100) * H;
  const line = (pts: (number | null)[]) => {
    let d = '';
    let pen = false;
    pts.forEach((v, i) => {
      if (v == null) return void (pen = false);
      d += `${pen ? 'L' : 'M'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`;
      pen = true;
    });
    return d;
  };
  useGSAP(() => {
    ref.current?.querySelectorAll<SVGPathElement>('path.series').forEach((p) => drawIn(p));
  }, { dependencies: [series.length], scope: ref });
  return (
    <figure className="chart">
      <svg ref={ref} viewBox={`0 -8 ${W} ${H + 24}`} role="img" aria-label="Drift per agent over the last 30 minutes">
        {[60, 75].map((t) => (
          <g key={t}>
            <line x1={0} x2={W} y1={y(t)} y2={y(t)} className={t === 60 ? 'th th-restrict' : 'th th-stepup'} />
            <text x={W - 4} y={y(t) - 4} textAnchor="end" className="th-label">{t === 60 ? 'Restrict 60' : 'Step-up 75'}</text>
          </g>
        ))}
        <line x1={0} x2={W} y1={H} y2={H} className="axis" />
        {series.map(([id, pts]) => {
          const last = trend.now.drift[id] ?? 0;
          const k = pts.map((p) => p.drift).findLastIndex((v) => v != null);
          return (
            <g key={id}>
              <path d={line(pts.map((p) => p.drift))} pathLength={1} className={`series s-${tierOf(last)}`}><title>{id}</title></path>
              {k >= 0 && <circle cx={x(k)} cy={y(pts[k].drift!)} r={4} className={`last s-${tierOf(last)}`}><title>{`${id}: ${Math.round(last)}`}</title></circle>}
            </g>
          );
        })}
        <text x={0} y={H + 16} className="th-label">30 min ago</text>
        <text x={W} y={H + 16} textAnchor="end" className="th-label">now</text>
      </svg>
      {!series.length && <figcaption className="muted">No drift yet. Lines appear as agents act.</figcaption>}
    </figure>
  );
}
