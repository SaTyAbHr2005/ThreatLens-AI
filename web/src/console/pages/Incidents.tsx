import { useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { deal, gsap, reduced, useGSAP } from '../../motion/gsap';
import { type Alert, api, API, ApiError, auth, ago, decisionLabel, type Replay, statusLabel, useApi } from '../api';
import { Empty, ErrorNote, Factors, Risk, Stamp } from '../ui';

let fromRow: DOMRect | null = null; // the clicked row, so the dossier can unfold out of it

export default function Incidents() {
  const { id } = useParams();
  const nav = useNavigate();
  const list = useApi<Alert[]>('/v1/alerts?limit=100', 5000);
  const root = useRef<HTMLDivElement>(null);
  useGSAP(() => deal(root.current), { dependencies: [list.data?.length], scope: root });

  const open = (a: Alert, el: HTMLElement) => {
    fromRow = reduced() ? null : el.getBoundingClientRect();
    nav(`/console/incidents/${a.id}`);
  };

  return (
    <div ref={root} className={id ? 'page incidents with-dossier' : 'page incidents'}>
      <section className="incident-list">
        <h2>Incidents</h2>
        <ErrorNote error={list.error} />
        {list.data && !list.data.length && <Empty>No incidents. Run the PDF attack from <Link to="/console/simulate">Simulate</Link> to see one.</Empty>}
        <ul className="rows">
          {list.data?.map((a) => (
            <li key={a.id} data-deal>
              <button className={a.id === id ? 'row-link sel' : 'row-link'} onClick={(e) => open(a, e.currentTarget)}>
                <span className="row-head">{a.headline}</span>
                <span className="row-meta muted">{a.agent_id} · {ago(a.ts)} · {a.status}</span>
                <Risk value={a.risk} />
              </button>
            </li>
          ))}
        </ul>
      </section>
      {id && <Dossier key={id} id={id} onChange={list.reload} />}
    </div>
  );
}

const STAMPS: Record<string, [string, string]> = {
  isolate: ['Isolated', 'every token revoked'],
  release: ['Released', 'back to its role'],
  mark_benign: ['Harmless', 'marked by analyst'],
  confirm_attack: ['Attack', 'confirmed by analyst'],
  approve_as_amendment: ['Approved', 'signed role amendment'],
};

function Dossier({ id, onChange }: { id: string; onChange: () => void }) {
  const alert = useApi<Alert>(`/v1/alerts/${id}`);
  const a = alert.data;
  const replay = useApi<Replay>(a ? `/v1/replay/${a.session_id}` : null);
  const [stamps, setStamps] = useState<string[]>([]);
  const [busy, setBusy] = useState('');
  const [err, setErr] = useState<Error | null>(null);
  const sheet = useRef<HTMLElement>(null);

  // Opening an incident: the dossier unfolds out of the row that was clicked (or slides onto the desk).
  useGSAP(() => {
    const el = sheet.current;
    if (!a || !el || reduced()) return;
    const s = el.getBoundingClientRect();
    if (fromRow) {
      const r = fromRow;
      const inset = `${r.top - s.top}px ${s.right - r.right}px ${s.bottom - r.bottom}px ${r.left - s.left}px`;
      gsap.fromTo(el, { clipPath: `inset(${inset} round 6px)` }, { clipPath: 'inset(0px 0px 0px 0px round 14px)', duration: 0.65, ease: 'expo.inOut', clearProps: 'clipPath' });
      gsap.from(el.children, { opacity: 0, duration: 0.4, delay: 0.3, stagger: 0.04 });
      fromRow = null;
    } else {
      gsap.from(el, { y: 24, opacity: 0, rotate: 0.4, duration: 0.6, ease: 'expo.out' });
    }
  }, { dependencies: [!!a] });

  if (alert.error) return <ErrorNote error={alert.error} />;
  if (!a) return <article className="dossier-sheet loading" aria-busy />;

  const act = async (kind: string) => {
    setBusy(kind);
    setErr(null);
    try {
      const why = `${STAMPS[kind][0]} from incident ${a.id}`;
      if (kind === 'isolate' || kind === 'release') {
        await api(`/v1/agents/${a.agent_id}/containment`, { method: 'POST', json: { action: kind, reason: why, actor: 'console' } });
      } else {
        await api(`/v1/alerts/${a.id}/feedback`, { method: 'POST', json: { feedback: kind, reason: why, actor: 'console' } });
      }
      setStamps((s) => [...s, kind]);
      alert.reload();
      replay.reload();
      onChange();
    } catch (e) {
      setErr(e as ApiError);
    } finally {
      setBusy('');
    }
  };

  const exportReport = async () => {
    const res = await fetch(`${API}/v1/alerts/${a.id}/dossier`, { headers: { Authorization: `Bearer ${auth.token}` } });
    const url = URL.createObjectURL(await res.blob());
    Object.assign(document.createElement('a'), { href: url, download: `${a.id}.md` }).click();
    URL.revokeObjectURL(url);
  };

  const cause = replay.data?.content.find((c) => c.id === a.cause_content_id);
  const steps = replay.data?.steps ?? [];
  return (
    <article ref={sheet} className="dossier-sheet paper-grain" aria-label="Incident dossier">
      <header className="dossier-head">
        <p className="muted">Incident dossier · <span className="mrz">{a.id}</span></p>
        <h1>{a.headline}</h1>
        {a.narrative && <p className="narrative">{a.narrative}</p>}
        <dl className="dossier-facts">
          <div><dt>Agent</dt><dd><Link to={`/console/agents?id=${a.agent_id}`}>{a.agent_id}</Link></dd></div>
          <div><dt>Risk</dt><dd><Risk value={a.risk} /></dd></div>
          <div><dt>Containment</dt><dd>{a.containment ? statusLabel[a.containment] : 'None'}</dd></div>
          <div><dt>Status</dt><dd>{a.status}{a.feedback ? `, ${a.feedback.replace(/_/g, ' ')}` : ''}</dd></div>
          <div><dt>When</dt><dd>{new Date(a.ts).toLocaleString()}</dd></div>
        </dl>
      </header>

      <section>
        <h2>Why it was flagged</h2>
        <Factors factors={a.factors} />
        {a.counterfactual && <p className="counterfactual">{a.counterfactual}</p>}
      </section>

      {a.decoded_injection && (
        <section>
          <h2>The hidden instruction</h2>
          <div className="reveal-pair">
            <div>
              <h3>What a person sees in {cause?.source.split('/').pop() ?? 'the content'}</h3>
              <p className="invisible-ink">{cause?.hidden_spans.length ? 'Nothing. The text is hidden with ' + cause.techniques.join(', ').replace(/_/g, ' ') + '.' : 'Nothing unusual.'}</p>
            </div>
            <div>
              <h3>What the model read</h3>
              <p className="decoded-ink mrz">{a.decoded_injection}</p>
            </div>
          </div>
        </section>
      )}

      {!!steps.length && (
        <section>
          <h2>What happened, in order</h2>
          <ol className="timeline">
            {steps.map((s) => (
              <li key={s.id} className={[a.timeline.includes(s.id) && 'hit', s.decision?.startsWith('allow') && 'allowed'].filter(Boolean).join(' ')}>
                <span className="mrz">{s.action.tool} {s.action.resource ?? s.action.destination ?? ''}</span>
                <span>{decisionLabel[s.decision ?? ''] ?? '–'}</span>
                <Risk value={s.risk} />
              </li>
            ))}
          </ol>
          <Link to={`/console/replay/${a.session_id}`} className="link">Replay this session</Link>
        </section>
      )}

      <section className="dossier-cols">
        {!!a.actions_taken.length && <div><h2>Actions taken</h2><ul>{a.actions_taken.map((x) => <li key={x}>{x}</li>)}</ul></div>}
        {!!a.recommendations.length && <div><h2>Recommended next</h2><ul>{a.recommendations.map((x) => <li key={x}>{x}</li>)}</ul></div>}
        {!!a.frameworks.length && <div><h2>Framework references</h2><ul>{a.frameworks.map((x) => <li key={x}>{x}</li>)}</ul></div>}
      </section>

      <ErrorNote error={err} />
      <footer className="dossier-actions">
        <button className="btn btn-void" disabled={!!busy} onClick={() => act('isolate')}>Isolate agent</button>
        <button className="btn" disabled={!!busy} onClick={() => act('release')}>Release agent</button>
        <button className="btn" disabled={!!busy} onClick={() => act('confirm_attack')}>Confirm attack</button>
        <button className="btn" disabled={!!busy} onClick={() => act('mark_benign')}>Mark as harmless</button>
        <button className="btn" disabled={!!busy} onClick={() => act('approve_as_amendment')}>Approve this change</button>
        <button className="btn btn-quiet" onClick={exportReport}>Export report</button>
      </footer>
      <div className="stamps" aria-live="polite">
        {stamps.map((k, i) => <Stamp key={i} text={STAMPS[k][0]} sub={STAMPS[k][1]} tone={k === 'release' || k === 'approve_as_amendment' || k === 'mark_benign' ? 'ink' : 'void'} />)}
      </div>
    </article>
  );
}
