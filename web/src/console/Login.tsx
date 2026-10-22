import { type FormEvent, useCallback, useEffect, useRef, useState } from 'react';
import { gsap, reduced, useGSAP } from '../motion/gsap';
import { ringPath, rosette } from '../passport/rosette';
import { Seal } from '../Seal';
import { api, ApiError, auth } from './api';

interface Challenge { token: string; target: number; track: number; piece: number; tolerance: number }
interface Point { t: number; x: number; y: number }

function deviceId() {
  try {
    let d = localStorage.getItem('tl.device');
    if (!d) localStorage.setItem('tl.device', (d = crypto.randomUUID()));
    return d;
  } catch {
    return 'no-storage-' + navigator.userAgent.length.toString(16).padStart(8, '0');
  }
}

export default function Login() {
  const root = useRef<HTMLDivElement>(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [ch, setCh] = useState<Challenge | null>(null);
  const [trail, setTrail] = useState<Point[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ title: string; detail?: string[] } | null>(null);

  const fresh = useCallback(() => {
    setTrail(null);
    api<Challenge>('/v1/auth/captcha', { method: 'POST' })
      .then(setCh)
      .catch((e: ApiError) => setError({ title: e.message }));
  }, []);
  useEffect(fresh, [fresh]);

  // The login seal engraves itself once: the console's arrival moment.
  useGSAP(() => {
    if (reduced()) return;
    gsap.from('.login-seal path', { strokeDashoffset: 1, duration: 2.2, ease: 'power2.inOut', stagger: 0.09 });
    gsap.from('.login-card > *', { opacity: 0, y: 8, duration: 0.5, ease: 'power3.out', stagger: 0.06, delay: 0.3 });
  }, { scope: root });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ch || !trail) return setError({ title: 'Slide the seal into the gap first.' });
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ token: string }>('/v1/auth/login', {
        method: 'POST',
        json: { email, password, device_id: deviceId(), captcha: { token: ch.token, trajectory: trail } },
      });
      auth.set(r.token);
    } catch (err) {
      const x = err as ApiError;
      const d = x.detail as { reasons?: string[] } | string;
      if (x.status === 403 && typeof d === 'object') {
        setError({ title: 'This sign-in looks unusual, so it was blocked. Ask an admin to approve it.', detail: d.reasons });
      } else if (x.status === 401) setError({ title: 'That email and password don’t match.' });
      else if (x.status === 429) setError({ title: 'Too many attempts. Wait 15 minutes, then try again.' });
      else setError({ title: typeof d === 'string' ? d.replace(/^CAPTCHA failed: /, 'The slider check failed: ') : x.message });
      fresh();
    } finally {
      setBusy(false);
    }
  };

  const rings = rosette('analyst-console');
  return (
    <div ref={root} className="login">
      <svg className="login-seal" viewBox="-1.02 -1.02 2.04 2.04" aria-hidden>
        {rings.map((_, i) => <path key={i} d={ringPath(rings, i, 0, 200)} pathLength={1} strokeDasharray={1} />)}
      </svg>
      <form className="login-card" onSubmit={submit}>
        <h1>Analyst sign-in</h1>
        <p className="muted">ThreatLens protects the people who protect the agents. A password alone doesn’t get in.</p>
        <label>Email<input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <label>Password<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <div>
          <p className="field-label" id="slider-label">Slide the seal into the gap</p>
          {ch ? <Slider ch={ch} done={!!trail} onDone={setTrail} /> : <div className="slider placeholder" />}
        </div>
        {error && (
          <div className="login-error" role="alert">
            <p>{error.title}</p>
            {error.detail && <ul>{error.detail.map((r) => <li key={r}>{r}</li>)}</ul>}
          </div>
        )}
        <button className="btn btn-foil" disabled={busy || !trail}>{busy ? 'Checking…' : 'Sign in'}</button>
        <p className="muted small">The way you drag the slider is checked too: scripts move in straight lines at constant speed.</p>
      </form>
    </div>
  );
}

/** Slider CAPTCHA: the track is a guilloche strip, the handle a small seal. Positions are in server pixels. */
function Slider({ ch, done, onDone }: { ch: Challenge; done: boolean; onDone: (t: Point[] | null) => void }) {
  const [x, setX] = useState(0);
  const drag = useRef<{ t0: number; x0: number; y0: number; pts: Point[] } | null>(null);
  const handle = useRef<HTMLButtonElement>(null);
  const max = ch.track - ch.piece;

  useEffect(() => setX(0), [ch.token]);

  const down = (e: React.PointerEvent) => {
    if (done) return;
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
    drag.current = { t0: performance.now(), x0: e.clientX - x, y0: e.clientY, pts: [{ t: 0, x, y: 0 }] };
  };
  const move = (e: React.PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const nx = Math.max(0, Math.min(max, e.clientX - d.x0));
    const t = performance.now() - d.t0;
    if (d.pts.length < 1900 && t - d.pts[d.pts.length - 1].t >= 8) d.pts.push({ t, x: nx, y: e.clientY - d.y0 });
    setX(nx);
  };
  const up = (e: React.PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    drag.current = null;
    const t = performance.now() - d.t0;
    d.pts.push({ t: Math.max(t, d.pts[d.pts.length - 1].t + 1), x, y: e.clientY - d.y0 });
    if (Math.abs(x - ch.target) <= ch.tolerance + 2) {
      onDone(d.pts);
    } else {
      onDone(null);
      const o = { v: x };
      gsap.to(o, { v: 0, duration: reduced() ? 0 : 0.45, ease: 'back.out(1.4)', onUpdate: () => setX(o.v) });
    }
  };

  return (
    <div className={done ? 'slider done' : 'slider'} style={{ width: ch.track, height: ch.piece + 8 }}>
      <span className="gap" style={{ left: ch.target, width: ch.piece, height: ch.piece }} aria-hidden />
      <button ref={handle} type="button" className="handle" aria-labelledby="slider-label"
        aria-valuemin={0} aria-valuemax={max} aria-valuenow={Math.round(x)} role="slider"
        style={{ transform: `translateX(${x}px)`, width: ch.piece, height: ch.piece }}
        onPointerDown={down} onPointerMove={move} onPointerUp={up} onPointerCancel={up}>
        <Seal size={26} />
      </button>
    </div>
  );
}
