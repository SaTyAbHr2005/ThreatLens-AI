import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { deal, useGSAP } from '../../motion/gsap';
import { ago, api, ApiError, type Approval, useApi } from '../api';
import { Empty, ErrorNote, Stamp } from '../ui';

export default function Approvals() {
  const list = useApi<Approval[]>('/v1/approvals', 4000);
  const [sel, setSel] = useState(0);
  const [done, setDone] = useState<Record<string, boolean>>({});
  const [err, setErr] = useState<ApiError | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const items = (list.data ?? []).filter((a) => a.status === 'pending' || a.id in done);
  useGSAP(() => deal(root.current), { dependencies: [items.length], scope: root });

  const decide = async (a: Approval, approve: boolean) => {
    setErr(null);
    try {
      await api(`/v1/approvals/${a.id}`, { method: 'POST', json: { approve, actor: 'console' } });
      setDone((d) => ({ ...d, [a.id]: approve }));
      setTimeout(list.reload, 1200);
    } catch (e) {
      setErr(e as ApiError);
    }
  };

  // a / d approve or deny the selected request; j / k move.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).closest('input, textarea, select') || e.metaKey || e.ctrlKey) return;
      const a = items[sel];
      if (e.key === 'j') setSel((s) => Math.min(items.length - 1, s + 1));
      if (e.key === 'k') setSel((s) => Math.max(0, s - 1));
      if (a && !(a.id in done) && (e.key === 'a' || e.key === 'd')) decide(a, e.key === 'a');
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  return (
    <div ref={root} className="page approvals">
      <h2>Approvals</h2>
      <p className="muted">Actions held at step-up. The agent waits while you decide. Keys: <kbd>a</kbd> approve, <kbd>d</kbd> deny, <kbd>j</kbd>/<kbd>k</kbd> move.</p>
      <ErrorNote error={err ?? list.error} />
      {list.data && !items.length && <Empty>Nothing is waiting. Held actions from agents at step-up appear here. <Link to="/console/simulate">Run a scenario</Link> to create one.</Empty>}
      <ul className="approval-list">
        {items.map((a, i) => (
          <li key={a.id} data-deal className={i === sel ? 'approval sel' : 'approval'} onClick={() => setSel(i)}>
            <div>
              <p className="mrz">{a.tool} {a.resource ?? a.destination ?? ''}</p>
              <p><b>{a.agent_id}</b> · {a.sensitivity} data · asked {ago(a.ts)}</p>
              <p className="muted">{a.reason}</p>
            </div>
            {a.id in done ? (
              <Stamp text={done[a.id] ? 'Approved' : 'Denied'} sub="by analyst" tone={done[a.id] ? 'ink' : 'void'} />
            ) : (
              <div className="approval-actions">
                <button className="btn" onClick={() => decide(a, true)}>Approve</button>
                <button className="btn btn-void" onClick={() => decide(a, false)}>Deny</button>
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
