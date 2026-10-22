import { useEffect, useMemo, useRef, useState } from 'react';
import { NavLink, Route, Routes, useLocation, useNavigate } from 'react-router';
import { gsap, reduced, useGSAP } from '../motion/gsap';
import { Seal } from '../Seal';
import { type Agent, api, auth, type Health, useApi } from './api';
import { startLive, stopLive, useLive } from './live';
import Login from './Login';
import Agents from './pages/Agents';
import Approvals from './pages/Approvals';
import Arena from './pages/Arena';
import Evaluation from './pages/Evaluation';
import Forensics from './pages/Forensics';
import Incidents from './pages/Incidents';
import Intel from './pages/Intel';
import Overview from './pages/Overview';
import Replay from './pages/Replay';
import Simulate, { SCENARIO_KEYS } from './pages/Simulate';
import './console.css';

const PAGES = [
  { path: '', label: 'Overview', key: 'o', el: <Overview /> },
  { path: 'agents', label: 'Agents', key: 'a', el: <Agents /> },
  { path: 'incidents', label: 'Incidents', key: 'i', el: <Incidents /> },
  { path: 'approvals', label: 'Approvals', key: 'p', el: <Approvals /> },
  { path: 'simulate', label: 'Simulate', key: 's', el: <Simulate /> },
  { path: 'forensics', label: 'Forensics', key: 'f', el: <Forensics /> },
  { path: 'intel', label: 'Intel', key: 'n', el: <Intel /> },
  { path: 'arena', label: 'Arena', key: 'm', el: <Arena /> },
  { path: 'replay', label: 'Replay', key: 'r', el: <Replay /> },
  { path: 'evaluation', label: 'Evaluation', key: 'e', el: <Evaluation /> },
];

export default function Console() {
  const [token, setToken] = useState(auth.token);
  useEffect(() => {
    document.title = 'ThreatLens console';
    const on = () => setToken(auth.token);
    window.addEventListener('tl-auth', on);
    return () => window.removeEventListener('tl-auth', on);
  }, []);
  useEffect(() => {
    if (!token) return;
    startLive();
    return stopLive;
  }, [token]);
  return <div className="console">{token ? <Shell /> : <Login />}</div>;
}

function Shell() {
  const main = useRef<HTMLElement>(null);
  const loc = useLocation();
  const nav = useNavigate();
  const [palette, setPalette] = useState(false);

  // Page change: the new page is laid down like a sheet sliding onto the desk.
  useGSAP(() => {
    if (reduced() || !main.current) return;
    gsap.fromTo(main.current, { opacity: 0, x: 14 }, { opacity: 1, x: 0, duration: 0.26, ease: 'power3.out' });
  }, { dependencies: [loc.pathname.split('/')[2] ?? ''] });

  // Keyboard: ⌘K palette, "g" then a letter to go to a page.
  useEffect(() => {
    let g = 0;
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPalette((p) => !p);
        return;
      }
      const t = e.target as HTMLElement;
      if (e.metaKey || e.ctrlKey || e.altKey || t.closest('input, textarea, select, [contenteditable]')) return;
      if (e.key === 'g') {
        g = Date.now();
        return;
      }
      if (Date.now() - g < 1200) {
        const p = PAGES.find((x) => x.key === e.key);
        if (p) nav(`/console/${p.path}`);
        g = 0;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [nav]);

  return (
    <div className="shell">
      <aside className="rail">
        <NavLink to="/" className="rail-mark"><Seal /> ThreatLens</NavLink>
        <nav aria-label="Console">
          {PAGES.map((p) => (
            <NavLink key={p.path} to={`/console/${p.path}`} end={p.path === ''}>
              {p.label}
              <kbd aria-hidden>g {p.key}</kbd>
            </NavLink>
          ))}
        </nav>
        <button className="rail-k" onClick={() => setPalette(true)}>Commands <kbd>⌘K</kbd></button>
      </aside>
      <StatusStrip />
      <main ref={main} className="main">
        <Routes>
          {PAGES.map((p) => <Route key={p.path} path={p.path} element={p.el} />)}
          <Route path="incidents/:id" element={<Incidents />} />
          <Route path="replay/:session" element={<Replay />} />
        </Routes>
      </main>
      {palette && <Palette onClose={() => setPalette(false)} />}
    </div>
  );
}

function StatusStrip() {
  const live = useLive();
  const agents = useApi<Agent[]>('/v1/agents', 5000);
  const [health, setHealth] = useState<Health | null>(null);
  const [gateway, setGateway] = useState<'warm' | 'waking' | 'down'>('warm');
  const pulse = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    let alive = true;
    const check = async () => {
      const slow = setTimeout(() => alive && setGateway('waking'), 6000);
      try {
        const h = await api<Health>('/v1/health');
        if (alive) {
          setHealth(h);
          setGateway('warm');
        }
      } catch {
        if (alive) setGateway('waking');
      } finally {
        clearTimeout(slow);
      }
    };
    check();
    const t = setInterval(check, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  // One pulse per live event: motion that answers something that happened, never an idle loop.
  useEffect(() => {
    if (!pulse.current || reduced() || !live.events.length) return;
    gsap.fromTo(pulse.current, { scale: 2.4, opacity: 0.2 }, { scale: 1, opacity: 1, duration: 0.5, ease: 'power3.out' });
  }, [live.events[0]?.id]);

  const list = agents.data ?? [];
  const intact = list.filter((a) => a.status === 'active').length;
  const me = useMemo(() => {
    try {
      return JSON.parse(atob((auth.token ?? '').split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))) as { name?: string; sub?: string };
    } catch {
      return {};
    }
  }, []);
  return (
    <header className="strip">
      <span className={intact < list.length ? 'chip chip-void' : 'chip'}>
        Fleet seal: <b className="num">{intact} of {list.length}</b> intact
      </span>
      <span className="chip">
        Gateway: {gateway === 'warm' ? 'warm' : 'waking up, about 30 s'}
      </span>
      <span className="chip">
        <span ref={pulse} className={live.connected ? 'dot on' : 'dot'} aria-hidden />
        {live.connected ? 'Live' : 'Reconnecting'}
      </span>
      {health?.llm.map((p) => (
        <span key={p.provider} className={p.ready ? 'chip' : 'chip chip-tarnish'} title={p.last_error ?? p.model}>
          {p.provider} {p.ready ? '✓' : `rate-limited, ${Math.ceil(p.cooldown_s)} s`}
        </span>
      ))}
      {health && !health.llm.length && <span className="chip" title="Explanations use templates">LLM: templates</span>}
      <span className="strip-me">
        {me.name ?? me.sub ?? 'Operator'}
        <button className="link" onClick={() => auth.set(null)}>Sign out</button>
      </span>
    </header>
  );
}

function Palette({ onClose }: { onClose: () => void }) {
  const nav = useNavigate();
  const [q, setQ] = useState('');
  const [i, setI] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const commands = useMemo(() => [
    ...PAGES.map((p) => ({ label: `Go to ${p.label}`, run: () => nav(`/console/${p.path}`) })),
    ...SCENARIO_KEYS.map((id) => ({
      label: `Run scenario ${id}`,
      run: () => nav(`/console/simulate?run=${id}`),
    })),
    { label: 'Open the landing page', run: () => nav('/') },
    { label: 'Sign out', run: () => auth.set(null) },
  ], [nav]);
  const shown = commands.filter((c) => c.label.toLowerCase().includes(q.toLowerCase()));
  useGSAP(() => {
    if (!reduced()) gsap.from(box.current, { opacity: 0, y: -10, scale: 0.98, duration: 0.2, ease: 'power3.out' });
  });
  const run = (n: number) => {
    shown[n]?.run();
    onClose();
  };
  return (
    <div className="palette-back" onMouseDown={onClose}>
      <div ref={box} className="palette" role="dialog" aria-label="Command palette" onMouseDown={(e) => e.stopPropagation()}>
        <input autoFocus placeholder="Type a command" value={q} aria-label="Command"
          onChange={(e) => (setQ(e.target.value), setI(0))}
          onKeyDown={(e) => {
            if (e.key === 'Escape') onClose();
            if (e.key === 'ArrowDown') setI((x) => Math.min(shown.length - 1, x + 1));
            if (e.key === 'ArrowUp') setI((x) => Math.max(0, x - 1));
            if (e.key === 'Enter') run(i);
          }} />
        <ul role="listbox">
          {shown.map((c, n) => (
            <li key={c.label} role="option" aria-selected={n === i} className={n === i ? 'on' : ''}
              onMouseEnter={() => setI(n)} onClick={() => run(n)}>{c.label}</li>
          ))}
          {!shown.length && <li className="muted">No command matches.</li>}
        </ul>
      </div>
    </div>
  );
}
