// The agent's behavioural signature: a guilloche rosette of nine rings, one per signal S0–S8.
// The same coefficients drive the WebGL shader, the 2D canvas fallback and the SVG on the landing.

export const SIGNALS = [
  { id: 'S0', name: 'Runtime fingerprint', question: 'Is this the same software, running from the same place, that was given the token?' },
  { id: 'S1', name: 'Role conformance', question: "Does this action fit the agent's job?" },
  { id: 'S2', name: 'Sequence surprise', question: 'Would this agent normally do this next?' },
  { id: 'S3', name: 'Session anomaly', question: 'Does this session look like its usual sessions?' },
  { id: 'S4', name: 'Provenance taint', question: 'Did it just read something untrusted that told it what to do?' },
  { id: 'S5', name: 'Sensitivity & egress', question: 'Is sensitive data heading somewhere new?' },
  { id: 'S6', name: 'Delegation chain', question: 'Is it borrowing authority from another agent?' },
  { id: 'S7', name: 'Slow drift', question: 'Has it been edging away from its role, one small step at a time?' },
  { id: 'S8', name: 'Canary resource', question: 'Did it touch a decoy that no real job needs?' },
] as const;

export const STRANDS = 3;
export const OUTER = 5; // rings S5–S8 are capabilities beyond the role: they clamp on containment

export interface Ring {
  R: number; // base radius, seal = 1
  n: number; // primary lobes
  a: number;
  m: number; // secondary lobes
  b: number;
  p: number; // phase
}

export interface Identity {
  name: string;
  role: string;
  roleVersion: number;
  owner: string;
  status: string;
  issued?: string;
}

export interface SealState {
  drift: number; // 0–1
  signals: number[]; // nine values 0–1
  clamp: number; // 0–1
}

export const CLEAN: SealState = { drift: 0, signals: Array(9).fill(0), clamp: 0 };

function fnv(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193);
  return h >>> 0;
}

function mulberry(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Deterministic per role: agents of one role share a signature family, as passports of one country do. */
export function rosette(seed: string): Ring[] {
  const r = mulberry(fnv(seed));
  return Array.from({ length: 9 }, (_, i) => {
    const n = 5 + Math.floor(r() * 9);
    return { R: 0.28 + i * 0.075, n, a: 0.026 + r() * 0.018, m: n * 2 + 1 + Math.floor(r() * 6), b: 0.005 + r() * 0.007, p: r() * Math.PI * 2 };
  });
}

export function ringBase(rings: Ring[], i: number, clamp: number) {
  const outer = i >= OUTER ? clamp : 0;
  return {
    R: rings[i].R + (rings[4].R + 0.032 * (i - 4) - rings[i].R) * outer,
    a: rings[i].a * (1 - 0.6 * outer),
  };
}

export function radius(g: Ring, R: number, a: number, strand: number, th: number, jitter = 0): number {
  return R + jitter + a * Math.sin(g.n * th + g.p + (2 * Math.PI * strand) / STRANDS) + g.b * Math.sin(g.m * th - g.p * 1.7);
}

/** SVG path (all strands of one ring) in a -1..1 box. */
export function ringPath(rings: Ring[], i: number, clamp = 0, steps = 280): string {
  const { R, a } = ringBase(rings, i, clamp);
  let d = '';
  for (let s = 0; s < STRANDS; s++) {
    for (let k = 0; k <= steps; k++) {
      const th = (k / steps) * Math.PI * 2;
      const r = radius(rings[i], R, a, s, th);
      d += `${k ? 'L' : 'M'}${(r * Math.cos(th)).toFixed(4)} ${(r * Math.sin(th)).toFixed(4)}`;
    }
  }
  return d;
}

// ---------------------------------------------------------------- 2D canvas

const INK = '#1c3a3f';
const TEAL = '#2f6e66';
const VOID = '#c8323c';
const TARNISH = [201, 162, 58];

function mix(a: number[], b: number[], t: number) {
  return a.map((v, i) => Math.round(v + (b[i] - v) * t));
}

/** The seal: foil disk, two-plate guilloche with misregistration as drift rises, VOID showing through. */
export function drawSeal(ctx: CanvasRenderingContext2D, cx: number, cy: number, size: number, rings: Ring[], s: SealState, dark = false) {
  const dull = Math.min(1, Math.max(0, (s.drift - 0.12) / 0.53));
  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, size * 0.975, 0, Math.PI * 2);
  ctx.clip();
  const foil = ctx.createConicGradient(-0.6, cx, cy);
  const hues = [[214, 228, 247], [236, 214, 240], [250, 236, 206], [212, 241, 226], [214, 228, 247]];
  hues.forEach((h, i) => foil.addColorStop(i / 4, `rgb(${mix(h, TARNISH, dull).join(',')})`));
  ctx.globalAlpha = dark ? 0.22 : 0.8;
  ctx.fillStyle = foil;
  ctx.fillRect(cx - size, cy - size, size * 2, size * 2);
  if (s.drift > 0.45) {
    ctx.globalAlpha = Math.min(0.75, (s.drift - 0.45) * 1.6);
    ctx.fillStyle = VOID;
    ctx.font = `800 ${size * 0.2}px "Archivo Variable", sans-serif`;
    ctx.translate(cx, cy);
    ctx.rotate(-0.35);
    for (let row = 0, y = -size * 1.2; y < size * 1.2; row++, y += size * 0.26) {
      for (let x = -size * 1.4 + (row % 2) * size * 0.31; x < size * 1.2; x += size * 0.62) ctx.fillText('VOID', x, y);
    }
    ctx.setTransform(1, 0, 0, 1, 0, 0);
  }
  ctx.restore();

  const shift = [s.drift * 0.035 * size, -s.drift * 0.022 * size];
  const steps = size > 120 ? 360 : 160;
  for (let i = 0; i < 9; i++) {
    const plate = i % 2;
    const { R, a } = ringBase(rings, i, s.clamp);
    const fire = s.signals[i] ?? 0;
    ctx.strokeStyle = fire > 0.5 ? VOID : dark ? (plate ? '#b9c7e8' : '#8db3aa') : plate ? TEAL : INK;
    ctx.globalAlpha = dark ? 0.8 : 0.72;
    ctx.lineWidth = Math.max(0.45, size * 0.0026 * (1 + 1.8 * fire));
    const ox = cx + (plate ? shift[0] : 0);
    const oy = cy + (plate ? shift[1] : 0);
    ctx.beginPath();
    for (let st = 0; st < STRANDS; st++) {
      for (let k = 0; k <= steps; k++) {
        const th = (k / steps) * Math.PI * 2;
        const r = radius(rings[i], R, a, st, th, s.drift * 0.02 * Math.sin(17 * th + i * 1.3)) * size;
        const x = ox + r * Math.cos(th);
        const y = oy + r * Math.sin(th);
        if (k) ctx.lineTo(x, y);
        else ctx.moveTo(x, y);
      }
    }
    ctx.stroke();
  }
  ctx.globalAlpha = 1;
}

// ---------------------------------------------------------------- card face (text + MRZ)

export const CARD = { w: 3.4, h: 2.4 }; // passport proportions; the 3D card uses the same units
export const SEAL = { x: 0.25, y: 0.44, r: 0.33 }; // centre in card fractions (y from top), radius in card heights

function mrzCheck(s: string): number {
  const w = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const v = c === '<' ? 0 : c >= '0' && c <= '9' ? +c : c.charCodeAt(0) - 55;
    sum += v * w[i % 3];
  }
  return sum % 10;
}

/** Two 44-character lines in passport MRZ format, with real ICAO 7-3-1 check digits. */
export function mrz(id: Identity): [string, string] {
  const clean = (s: string) => s.toUpperCase().replace(/[^A-Z0-9]+/g, '<');
  const l1 = `P<TLS${clean(id.role)}<<${clean(id.name)}`.padEnd(44, '<').slice(0, 44);
  const doc = clean(id.name.split('-').pop() ?? 'AGENT').padEnd(9, '<').slice(0, 9);
  const date = (id.issued ?? new Date().toISOString()).slice(2, 10).replace(/-/g, '');
  const body = `${doc}${mrzCheck(doc)}TLS${date}${mrzCheck(date)}V${String(id.roleVersion).padStart(2, '0')}<${clean(id.status)}`;
  const l2 = body.padEnd(43, '<').slice(0, 43);
  return [l1, l2 + mrzCheck(l2)];
}

/** Text layer of the card. Transparent background, so the WebGL card can use it as a texture. */
export function drawCardText(ctx: CanvasRenderingContext2D, w: number, h: number, id: Identity) {
  const u = w / 100;
  ctx.fillStyle = INK;
  ctx.textBaseline = 'alphabetic';
  ctx.font = `620 ${u * 2.2}px "Archivo Variable", sans-serif`;
  ctx.fillText('ThreatLens · Agent passport', u * 5, u * 6.4);
  ctx.textAlign = 'right';
  ctx.fillText(`Role contract v${id.roleVersion}`, w - u * 5, u * 6.4);
  ctx.textAlign = 'left';

  const x = w * 0.5;
  const fields: [string, string][] = [
    ['Agent', id.name],
    ['Role', id.role],
    ['Owner', id.owner],
    ['Status', id.status.replace('_', '-')],
  ];
  fields.forEach(([label, value], i) => {
    const y = u * (16 + i * 10.4);
    ctx.fillStyle = TEAL;
    ctx.font = `500 ${u * 1.9}px "Archivo Variable", sans-serif`;
    ctx.fillText(label, x, y);
    ctx.fillStyle = label === 'Status' && id.status !== 'active' ? VOID : INK;
    ctx.font = `720 ${u * (label === 'Agent' ? 3.3 : 2.9)}px "Archivo Variable", sans-serif`;
    ctx.fontStretch = 'expanded';
    let v = value;
    while (ctx.measureText(v).width > w * 0.45 && v.length > 4) v = v.slice(0, -2);
    ctx.fillText(v === value ? v : `${v}…`, x, y + u * 4);
    ctx.fontStretch = 'normal';
  });

  ctx.fillStyle = 'rgba(28,58,63,0.07)';
  ctx.fillRect(0, h * 0.79, w, h * 0.21);
  ctx.fillStyle = INK;
  ctx.font = `400 ${u * 3.4}px "OCR-B", "Courier Prime", monospace`;
  const [l1, l2] = mrz(id);
  const pitch = (w - u * 8) / 44;
  [l1, l2].forEach((line, row) => {
    for (let i = 0; i < line.length; i++) ctx.fillText(line[i], u * 4 + i * pitch, h * (0.87 + row * 0.085));
  });
}

/** Whole card in 2D: the fallback poster, the console's mini passports and replay. */
export function drawCard(canvas: HTMLCanvasElement, id: Identity, s: SealState, cssWidth: number) {
  const dpr = Math.max(2, Math.min(3, window.devicePixelRatio || 1));
  const w = Math.round(cssWidth * dpr);
  const h = Math.round((w * CARD.h) / CARD.w);
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  ctx.fillStyle = '#dce3da';
  ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = 'rgba(47,110,102,0.13)';
  ctx.lineWidth = Math.max(1, w / 900);
  for (let y = 0; y < h; y += h / 46) {
    ctx.beginPath();
    for (let x = 0; x <= w; x += w / 60) ctx.lineTo(x, y + Math.sin((x / w) * 18 + (y / h) * 4) * (h / 46) * 0.35);
    ctx.stroke();
  }
  drawSeal(ctx, w * SEAL.x, h * SEAL.y, h * SEAL.r, rosette(id.role), s);
  drawCardText(ctx, w, h, id);
}
