import { type MouseEvent, useState } from 'react';
import { flushSync } from 'react-dom';
import { reduced } from './motion/gsap';

type Theme = 'light' | 'dark';
const KEY = 'tl.theme';

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'light' || v === 'dark' ? v : null;
  } catch {
    return null;
  }
}

/** Before the first paint, so a saved theme never flashes the other one. */
export function applyStoredTheme() {
  const t = stored();
  if (t) document.documentElement.dataset.theme = t;
}

/** `base` is the surface's own ground, used until someone picks a theme. */
export function ThemeToggle({ base, className = '' }: { base: Theme; className?: string }) {
  const [theme, setTheme] = useState<Theme>(() => stored() ?? base);
  const next: Theme = theme === 'dark' ? 'light' : 'dark';

  const flip = (e: MouseEvent<HTMLButtonElement>) => {
    const apply = () => {
      document.documentElement.dataset.theme = next;
      try {
        localStorage.setItem(KEY, next);
      } catch { /* private window: the choice lasts until reload */ }
      flushSync(() => setTheme(next));
    };
    if (!('startViewTransition' in document) || reduced()) return apply();
    // The new theme spreads out from the button until it covers the farthest corner.
    const r = e.currentTarget.getBoundingClientRect();
    const x = r.left + r.width / 2;
    const y = r.top + r.height / 2;
    const end = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
    document.startViewTransition(apply).ready.then(() => {
      document.documentElement.animate(
        { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${end}px at ${x}px ${y}px)`] },
        { duration: 700, easing: 'cubic-bezier(0.65, 0, 0.35, 1)', pseudoElement: '::view-transition-new(root)' },
      );
    });
  };

  return (
    <button type="button" className={`theme-toggle ${className}`} data-theme-now={theme} onClick={flip}
      aria-label={`Switch to ${next} theme`} title={`Switch to ${next} theme`}>
      <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden>
        <circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <path d="M12 3.5a8.5 8.5 0 0 1 0 17z" fill="currentColor" />
        <circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" strokeWidth="1" strokeDasharray="1.5 1.5" />
      </svg>
    </button>
  );
}
