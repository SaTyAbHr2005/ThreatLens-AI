import { useEffect, useRef, useState } from 'react';
import type { PassportHandle } from './passport3d';
import { CARD, drawCard, type Identity, type SealState } from './rosette';

export const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function canWebGL(): boolean {
  if (window.innerWidth < 768 || (navigator.hardwareConcurrency ?? 8) <= 4) return false;
  try {
    return !!document.createElement('canvas').getContext('webgl2');
  } catch {
    return false;
  }
}

interface Props extends Partial<SealState> {
  identity: Identity;
  /** 2D only: mini passports in lists, where many WebGL contexts would be wasteful. */
  flat?: boolean;
  className?: string;
}

/** `<AgentPassport>`: a 2D poster first, then the WebGL card once its chunk loads (DESIGN.md §3.2). */
export function AgentPassport({ identity, drift = 0, signals, clamp = 0, flat, className }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const poster = useRef<HTMLCanvasElement>(null);
  const handle = useRef<PassportHandle | null>(null);
  const [live, setLive] = useState(false);
  const [width, setWidth] = useState(0);
  const sig = signals ?? Array(9).fill(0);
  const sigKey = sig.map((v) => v.toFixed(2)).join();
  const idKey = `${identity.name}|${identity.role}|${identity.roleVersion}|${identity.status}|${identity.owner}`;
  const latest = useRef({ identity, drift, clamp, sig });
  latest.current = { identity, drift, clamp, sig };

  useEffect(() => {
    const ro = new ResizeObserver(([e]) => setWidth(Math.round(e.contentRect.width / 40) * 40));
    if (host.current) ro.observe(host.current);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (live || !poster.current || !width) return;
    drawCard(poster.current, identity, { drift, signals: sig, clamp }, width);
  }, [live, width, drift, clamp, sigKey, idKey]);

  useEffect(() => {
    const el = host.current;
    if (flat || !el || !canWebGL()) return;
    let gone = false;
    import('./passport3d').then(({ mountPassport }) => {
      if (gone) return;
      // Props may have changed while the chunk loaded: mount with the latest ones.
      const now = latest.current;
      handle.current = mountPassport(el, now.identity, reducedMotion(), () => !gone && setLive(true));
      handle.current.update({ drift: now.drift, signals: now.sig, clamp: now.clamp }, true);
    });
    return () => {
      gone = true;
      handle.current?.dispose();
      handle.current = null;
      setLive(false);
    };
  }, [flat, identity.role]);

  useEffect(() => {
    handle.current?.update({ drift, clamp, signals: sig });
  }, [drift, clamp, sigKey]);

  useEffect(() => {
    handle.current?.setIdentity(identity);
  }, [idKey]);

  const label = `Agent passport for ${identity.name}, role ${identity.role}, status ${identity.status}, drift ${Math.round(drift * 100)} of 100`;
  return (
    <div ref={host} className={className} role="img" aria-label={label}
      style={{ position: 'relative', aspectRatio: flat ? `${CARD.w} / ${CARD.h}` : undefined }}>
      <canvas ref={poster} aria-hidden
        style={{ width: '100%', height: 'auto', display: live ? 'none' : 'block', borderRadius: 'var(--r-doc)',
          boxShadow: flat ? 'none' : 'var(--lift)', position: flat ? 'static' : 'absolute', top: '50%', left: 0,
          transform: flat ? undefined : 'translateY(-50%)' }} />
    </div>
  );
}
