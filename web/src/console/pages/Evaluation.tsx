import { useRef } from 'react';
import { countUp, deal, useGSAP } from '../../motion/gsap';
import { useApi } from '../api';
import { Empty, ErrorNote } from '../ui';

interface At { detection_rate: number; false_positive_rate: number; by_scenario: Record<string, number>; held_out_variant_detection_rate: number; false_alerts_per_1k_benign_actions: number }
interface Results {
  generated_at: string;
  embedder: string;
  dataset: { test_sessions: number; test_benign_actions: number; test_attack_sessions: number; test_held_out_variants: number };
  ablation: { config: string; description: string; signals: string[]; at_threshold: At; at_matched_fpr: At }[];
  outcomes: {
    legit_work_preserved: number; malicious_actions_blocked: number; exfil_bytes_reached_sink: number; attribution_accuracy: number;
    latency_ms: { score_p50: number; score_p95: number; call_p95: number };
  };
  scenarios: { id: string; name: string; passed: boolean }[];
}

const p = (v: number) => `${Math.round(v * 100)}%`;

export default function Evaluation() {
  const r = useApi<Results>('/v1/eval/latest');
  const root = useRef<HTMLDivElement>(null);
  useGSAP(() => {
    root.current?.querySelectorAll<HTMLElement>('[data-to]').forEach((el) => countUp(el, +el.dataset.to!, +(el.dataset.dec ?? 0), el.dataset.suf));
    deal(root.current, 'tbody tr');
  }, { dependencies: [!!r.data], scope: root });

  if (r.error?.status === 404) return <div className="page"><Empty>Evaluation in progress. No results file yet.</Empty></div>;
  const d = r.data;
  if (!d) return <div className="page"><ErrorNote error={r.error} /></div>;
  const o = d.outcomes;
  const scen = Object.keys(d.ablation[0]?.at_threshold.by_scenario ?? {});
  return (
    <div ref={root} className="page evaluation">
      <h2>Evaluation</h2>
      <p className="muted">{d.dataset.test_sessions} test sessions: {d.dataset.test_benign_actions.toLocaleString()} legitimate actions and {d.dataset.test_attack_sessions} attacks ({d.dataset.test_held_out_variants} held-out variants). Embedder {d.embedder}. Generated {new Date(d.generated_at).toLocaleString()}.</p>
      <section className="tiles">
        {([
          [o.legit_work_preserved * 100, 0, '%', 'legitimate actions allowed'],
          [o.malicious_actions_blocked * 100, 0, '%', 'malicious actions blocked'],
          [o.exfil_bytes_reached_sink, 0, '', 'bytes reached the attacker'],
          [o.attribution_accuracy * 100, 0, '%', 'attribution accuracy'],
          [o.latency_ms.score_p95, 2, ' ms', 'scoring p95'],
        ] as const).map(([v, dec, suf, label]) => (
          <div key={label} className="tile">
            <span className="num tile-v" data-to={v} data-dec={dec} data-suf={suf}>{v.toFixed(dec)}{suf}</span>
            <span className="muted">{label}</span>
          </div>
        ))}
      </section>
      <section className="panel">
        <h3>Ablation: attacks detected, by what the defender can see</h3>
        <table className="table">
          <thead>
            <tr><th>Configuration</th><th>Signals</th><th>At risk ≥ 60</th><th>At 2% FPR</th>{scen.map((s) => <th key={s}>{s}</th>)}<th>Held-out</th><th>False alerts / 1k</th></tr>
          </thead>
          <tbody>
            {d.ablation.map((a) => (
              <tr key={a.config} className={a.config === 'full' ? 'us' : ''}>
                <td>{a.description}</td>
                <td className="mrz small">{a.signals.join(' ') || 'none'}</td>
                <td className="num">{p(a.at_threshold.detection_rate)}</td>
                <td className="num">{p(a.at_matched_fpr.detection_rate)}</td>
                {scen.map((s) => <td key={s} className="num">{p(a.at_matched_fpr.by_scenario[s])}</td>)}
                <td className="num">{p(a.at_threshold.held_out_variant_detection_rate)}</td>
                <td className="num">{a.at_threshold.false_alerts_per_1k_benign_actions.toFixed(1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted small">Per-scenario columns are at the matched false-positive rate.</p>
      </section>
      <section className="panel">
        <h3>Scenario regression suite</h3>
        <ul className="scenario-pills">
          {d.scenarios.map((s) => <li key={s.id} className={s.passed ? 'pass' : 'fail'}><b>{s.id}</b> {s.name} · {s.passed ? 'passes' : 'fails'}</li>)}
        </ul>
      </section>
    </div>
  );
}
