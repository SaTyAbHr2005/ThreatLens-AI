import { useEffect, useRef, useState } from 'react';
import { deal, useGSAP } from '../../motion/gsap';
import { api, ApiError, type ArenaRun, type Signature, useApi } from '../api';
import { useLive } from '../live';
import { Empty, ErrorNote, Stamp } from '../ui';

const VERDICT: Record<string, string> = {
  exfiltrated: 'Followed it and tried to send data out', followed: 'Followed it', resisted: 'Ignored it', error: 'No answer',
};

export default function Arena() {
  const models = useApi<string[]>('/v1/arena/models');
  const sigs = useApi<Signature[]>('/v1/intel/signatures');
  const runs = useApi<ArenaRun[]>('/v1/arena/runs', 0);
  const [run, setRun] = useState<ArenaRun | null>(null);
  const [err, setErr] = useState<ApiError | null>(null);
  const live = useLive();
  const root = useRef<HTMLDivElement>(null);
  useGSAP(() => deal(root.current, '.arena-row'), { dependencies: [run?.results.length], scope: root });

  // Results stream in over the WebSocket; refetch the run as each model answers.
  useEffect(() => {
    if (!run || run.status === 'done') return;
    api<ArenaRun>(`/v1/arena/runs/${run.id}`).then(setRun).catch(() => {});
  }, [live.arena.length]);
  useEffect(() => {
    if (!run || run.status === 'done') return;
    const t = setInterval(() => api<ArenaRun>(`/v1/arena/runs/${run.id}`).then(setRun).catch(() => {}), 3000);
    return () => clearInterval(t);
  }, [run?.id, run?.status]);

  const start = async () => {
    setErr(null);
    try {
      const sig = sigs.data?.[0];
      setRun(await api<ArenaRun>('/v1/arena/run', { method: 'POST', json: sig ? { signature_id: sig.id } : {} }));
    } catch (e) {
      setErr(e as ApiError);
    }
  };

  const shown = run ?? runs.data?.[0] ?? null;
  const followed = shown?.results.filter((r) => r.verdict === 'followed' || r.verdict === 'exfiltrated').length ?? 0;
  return (
    <div ref={root} className="page arena">
      <h2>LLM Susceptibility Arena</h2>
      <p className="muted">The same poisoned document, given to every free model behind sandboxed tools. Which ones follow the hidden instruction?</p>
      <div className="form-row">
        <button className="btn btn-void" onClick={start} disabled={run?.status === 'running' || !models.data?.length}>
          {run?.status === 'running' ? 'Models are answering…' : 'Run against all models'}
        </button>
        <span className="muted small">{models.data?.length ? models.data.join(' · ') : 'No LLM provider keys are configured on the API.'}</span>
      </div>
      <ErrorNote error={err} />
      {!shown && <Empty>No runs yet. It uses the latest injection signature, or the A1 instruction if there is none.</Empty>}
      {shown && (
        <article className="panel">
          <p className="mrz small">{shown.instruction}</p>
          <table className="table">
            <thead><tr><th>Model</th><th>What it did</th><th>Tool calls</th><th>Time</th></tr></thead>
            <tbody>
              {shown.results.map((r) => (
                <tr key={r.provider + r.model} className={`arena-row v-${r.verdict}`}>
                  <td><b>{r.provider}</b> <span className="muted small">{r.model}</span></td>
                  <td>{VERDICT[r.verdict] ?? r.verdict}</td>
                  <td className="mrz small">{r.tool_calls.map((c) => c.name).join(', ') || '–'}</td>
                  <td className="num">{(r.latency_ms / 1000).toFixed(1)} s</td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.status === 'done' && <Stamp key={shown.id} text={`${followed} of ${shown.results.length}`} sub="models followed it" tone={followed ? 'void' : 'ink'} />}
        </article>
      )}
    </div>
  );
}
