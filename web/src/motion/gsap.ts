import { useGSAP } from '@gsap/react';
import gsap from 'gsap';
import { ScrambleTextPlugin } from 'gsap/ScrambleTextPlugin';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { SplitText } from 'gsap/SplitText';

gsap.registerPlugin(useGSAP, ScrollTrigger, SplitText, ScrambleTextPlugin);

export { gsap, ScrollTrigger, SplitText, useGSAP };

export const reduced = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/** Rubber stamp landing: short overshoot, then a 2px ink spread (DESIGN.md §4). */
export function stamp(el: Element | null) {
  if (!el) return;
  if (reduced()) {
    gsap.set(el, { opacity: 1, scale: 1 });
    return;
  }
  gsap.timeline()
    .fromTo(el, { opacity: 0, scale: 1.9, rotate: -18 }, { opacity: 1, scale: 0.94, rotate: -8, duration: 0.32, ease: 'expo.in' })
    .to(el, { scale: 1, duration: 0.35, ease: 'expo.out' })
    .fromTo(el, { filter: 'blur(0px)' }, { filter: 'blur(0.6px)', duration: 0.5, ease: 'power2.out' }, '<');
}

/** Console lists: rows are dealt in, one after another, when their data arrives. */
export function deal(scope: Element | null, selector = '[data-deal]') {
  if (!scope || reduced()) return;
  const els = scope.querySelectorAll(selector);
  if (els.length) gsap.fromTo(els, { opacity: 0, x: -12 }, { opacity: 1, x: 0, duration: 0.34, ease: 'power3.out', stagger: 0.035, overwrite: true });
}

/** A line chart path draws itself. */
export function drawIn(path: SVGPathElement | null) {
  if (!path || reduced()) return;
  gsap.fromTo(path, { strokeDasharray: 1, strokeDashoffset: 1 }, { strokeDashoffset: 0, duration: 1.1, ease: 'power2.inOut' });
}

/** Count a number up from zero when it scrolls into view (or changes). */
export function countUp(el: HTMLElement | null, to: number, decimals = 0, suffix = '') {
  if (!el) return;
  const write = (v: number) => (el.textContent = v.toFixed(decimals) + suffix);
  if (reduced()) return write(to);
  const o = { v: 0 };
  gsap.to(o, { v: to, duration: 1.2, ease: 'power3.out', onUpdate: () => write(o.v) });
}
