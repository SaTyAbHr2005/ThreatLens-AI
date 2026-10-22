// The 3D Agent Passport (DESIGN.md §3). Lazy-loaded: three.js never ships in the first-paint bundle.
import gsap from 'gsap';
import * as THREE from 'three';
import { CARD, CLEAN, drawCardText, type Identity, rosette, SEAL, type SealState } from './rosette';

const vert = /* glsl */ `
uniform vec2 uSize;
varying vec2 vUv;
varying float vFront;
void main() {
  vUv = position.xy / uSize + 0.5;
  vFront = step(0.0, normal.z);
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}`;

const frag = /* glsl */ `
varying vec2 vUv;
varying float vFront;
uniform float uR[9], uN[9], uA[9], uM[9], uB[9], uP[9], uSig[9];
uniform float uDrift, uClamp, uTime, uAspect, uSealR;
uniform vec2 uTilt, uSeal;
uniform sampler2D uText, uVoid;

const vec3 PAPER = vec3(0.863, 0.890, 0.855);
const vec3 INK = vec3(0.110, 0.227, 0.247);
const vec3 TEAL = vec3(0.184, 0.431, 0.400);
const vec3 TARNISH = vec3(0.788, 0.635, 0.227);
const vec3 VOIDC = vec3(0.784, 0.196, 0.235);

float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
float noise(vec2 p) {
  vec2 i = floor(p), f = fract(p), u = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1, 0)), u.x), mix(hash(i + vec2(0, 1)), hash(i + vec2(1, 1)), u.x), u.y);
}

// One printing plate of the rosette: even rings or odd rings. Returns coverage; fire = coverage of firing rings.
float plate(vec2 q, float which, out float fire) {
  float rho = length(q), th = atan(q.y, q.x);
  float aa = fwidth(rho) * 1.2;
  float ink = 0.0;
  fire = 0.0;
  for (int i = 0; i < 9; i++) {
    float fi = float(i);
    if (mod(fi, 2.0) != which) continue;
    float outer = step(4.5, fi) * uClamp;
    float R = mix(uR[i], uR[4] + 0.032 * (fi - 4.0), outer);
    float amp = uA[i] * (1.0 - 0.6 * outer);
    float jit = uDrift * 0.02 * sin(17.0 * th + fi * 1.3 + uTime * 0.7);
    float w = 0.0016 * (1.0 + 1.8 * uSig[i]);
    for (int j = 0; j < 3; j++) {
      float r = R + jit + amp * sin(uN[i] * th + uP[i] + 2.0943951 * float(j)) + uB[i] * sin(uM[i] * th - uP[i] * 1.7);
      float l = 1.0 - smoothstep(w, w + aa, abs(rho - r));
      ink = max(ink, l);
      fire = max(fire, l * uSig[i]);
    }
  }
  return ink;
}

void main() {
  vec3 col = PAPER;
  float wav = abs(fract(vUv.y * 46.0 + 0.35 * sin(vUv.x * 18.0 + vUv.y * 4.0)) - 0.5);
  col = mix(col, TEAL, (1.0 - smoothstep(0.03, 0.08, wav)) * 0.12);
  if (vFront < 0.5) { gl_FragColor = vec4(col * 0.96, 1.0); return; }

  vec2 q = vec2((vUv.x - uSeal.x) * uAspect, vUv.y - uSeal.y) / uSealR;
  float rho = length(q);
  float disk = 1.0 - smoothstep(0.965, 0.98, rho);

  // Holographic foil: thin-film interference, hue follows the viewing angle (pointer tilt).
  float film = 0.55 * rho + 0.35 * dot(q, vec2(0.6, 0.8)) + uTilt.x * 0.9 - uTilt.y * 0.6 + 0.06 * sin(uTime * 0.5);
  vec3 irid = mix(vec3(0.86, 0.89, 0.93), 0.5 + 0.5 * cos(6.2831853 * (film + vec3(0.0, 0.33, 0.67))), 0.4);
  float dull = smoothstep(0.12, 0.65, uDrift);
  vec3 foil = mix(irid, TARNISH * 0.95 + 0.04, dull);
  float sheen = pow(max(0.0, 1.0 - abs(q.x * 0.7 + q.y * 0.7 - (uTilt.x - uTilt.y) * 1.6) * 1.5), 8.0) * (1.0 - dull);
  col = mix(col, foil + sheen * 0.35, disk * 0.85);

  // Tamper tape: the VOID pattern breaks through in patches as drift rises.
  float tamper = disk * step(noise(q * 3.2 + 7.0), uDrift * 1.3 - 0.45);

  // Two plates; drift pulls them out of register like a misprinted banknote.
  float f0, f1;
  float l0 = plate(q, 0.0, f0);
  float l1 = plate(q + uDrift * vec2(0.035, -0.022), 1.0, f1);
  col = mix(col, mix(INK, VOIDC, clamp(f0 / max(l0, 1e-3), 0.0, 1.0)), l0 * 0.8);
  col = mix(col, mix(TEAL, VOIDC, clamp(f1 / max(l1, 1e-3), 0.0, 1.0)), l1 * 0.8);
  // The VOID text is printed on top: once the seal breaks, it reads through the guilloche.
  col = mix(col, mix(col, PAPER, 0.55), tamper * 0.7);
  col = mix(col, VOIDC, tamper * texture2D(uVoid, q * 1.4).a * 0.95);

  vec4 t = texture2D(uText, vUv);
  col = mix(col, t.rgb, t.a);
  float edge = min(min(vUv.x, 1.0 - vUv.x), min(vUv.y, 1.0 - vUv.y));
  col *= 0.965 + 0.035 * smoothstep(0.0, 0.05, edge);
  gl_FragColor = vec4(col, 1.0);
}`;

function roundedRect(w: number, h: number, r: number) {
  const s = new THREE.Shape();
  s.moveTo(-w / 2 + r, -h / 2);
  s.lineTo(w / 2 - r, -h / 2);
  s.quadraticCurveTo(w / 2, -h / 2, w / 2, -h / 2 + r);
  s.lineTo(w / 2, h / 2 - r);
  s.quadraticCurveTo(w / 2, h / 2, w / 2 - r, h / 2);
  s.lineTo(-w / 2 + r, h / 2);
  s.quadraticCurveTo(-w / 2, h / 2, -w / 2, h / 2 - r);
  s.lineTo(-w / 2, -h / 2 + r);
  s.quadraticCurveTo(-w / 2, -h / 2, -w / 2 + r, -h / 2);
  return s;
}

function voidTexture() {
  const c = document.createElement('canvas');
  c.width = c.height = 256;
  const ctx = c.getContext('2d')!;
  ctx.font = '800 54px "Archivo Variable", sans-serif';
  ctx.translate(128, 128);
  ctx.rotate(-0.35);
  for (let row = 0, y = -200; y < 220; row++, y += 64) for (let x = -230 + (row % 2) * 70; x < 230; x += 140) ctx.fillText('VOID', x, y);
  const t = new THREE.CanvasTexture(c);
  t.wrapS = t.wrapT = THREE.RepeatWrapping;
  return t;
}

export interface PassportHandle {
  update(s: Partial<SealState>, instant?: boolean): void;
  setIdentity(id: Identity): void;
  dispose(): void;
}

export function mountPassport(host: HTMLElement, identity: Identity, reduced: boolean, onReady: () => void): PassportHandle {
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
  renderer.setPixelRatio(Math.min(1.75, Math.max(1, window.devicePixelRatio)));
  renderer.domElement.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;';
  host.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(30, 1, 0.1, 50);

  const text = document.createElement('canvas');
  text.width = 2048;
  text.height = Math.round((2048 * CARD.h) / CARD.w);
  const textTex = new THREE.CanvasTexture(text);
  textTex.anisotropy = renderer.capabilities.getMaxAnisotropy();
  const paintText = (id: Identity) => {
    const ctx = text.getContext('2d')!;
    ctx.clearRect(0, 0, text.width, text.height);
    drawCardText(ctx, text.width, text.height, id);
    textTex.needsUpdate = true;
  };

  const rings = rosette(identity.role);
  const pick = (k: 'R' | 'n' | 'a' | 'm' | 'b' | 'p') => ({ value: rings.map((r) => r[k]) });
  const u = {
    uR: pick('R'), uN: pick('n'), uA: pick('a'), uM: pick('m'), uB: pick('b'), uP: pick('p'),
    uSig: { value: [...CLEAN.signals] },
    uDrift: { value: 0 }, uClamp: { value: 0 }, uTime: { value: 0 },
    uAspect: { value: CARD.w / CARD.h }, uSealR: { value: SEAL.r },
    uSeal: { value: new THREE.Vector2(SEAL.x, 1 - SEAL.y) },
    uTilt: { value: new THREE.Vector2() },
    uSize: { value: new THREE.Vector2(CARD.w, CARD.h) },
    uText: { value: textTex }, uVoid: { value: voidTexture() },
  };
  const face = new THREE.ShaderMaterial({ uniforms: u, vertexShader: vert, fragmentShader: frag });
  const edge = new THREE.MeshBasicMaterial({ color: '#b9c4b8' });
  const geo = new THREE.ExtrudeGeometry(roundedRect(CARD.w, CARD.h, 0.16), {
    depth: 0.03, bevelEnabled: true, bevelThickness: 0.012, bevelSize: 0.012, bevelSegments: 3, curveSegments: 10,
  });
  geo.center();
  const card = new THREE.Mesh(geo, [face, edge]);
  scene.add(card);

  const fit = () => {
    const { width, height } = host.getBoundingClientRect();
    if (!width || !height) return;
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    const k = 2 * Math.tan((camera.fov * Math.PI) / 360);
    camera.position.z = Math.max(CARD.h / 0.84 / k, CARD.w / 0.86 / (k * camera.aspect));
    camera.updateProjectionMatrix();
  };
  const ro = new ResizeObserver(fit);
  ro.observe(host);
  fit();

  const pointer = { x: 0, y: 0, active: false };
  const onMove = (e: PointerEvent) => {
    const r = host.getBoundingClientRect();
    pointer.x = Math.max(-1, Math.min(1, (e.clientX - (r.left + r.width / 2)) / (r.width * 0.8)));
    pointer.y = Math.max(-1, Math.min(1, (e.clientY - (r.top + r.height / 2)) / (r.height * 0.8)));
    pointer.active = true;
  };
  if (!reduced) window.addEventListener('pointermove', onMove, { passive: true });

  // Render only while on screen and the tab is visible.
  let visible = true;
  let raf = 0;
  const clock = new THREE.Clock();
  const frame = () => {
    raf = 0;
    if (!visible || document.hidden) return;
    const t = clock.getElapsedTime();
    u.uTime.value = reduced ? 0 : t;
    const tx = pointer.active ? pointer.x : reduced ? 0 : Math.sin(t * 0.45) * 0.35;
    const ty = pointer.active ? pointer.y : reduced ? 0 : Math.cos(t * 0.33) * 0.2;
    card.rotation.y += (tx * 0.38 - card.rotation.y) * 0.08;
    card.rotation.x += (ty * 0.26 - card.rotation.x) * 0.08;
    u.uTilt.value.set(card.rotation.y, card.rotation.x);
    renderer.render(scene, camera);
    raf = requestAnimationFrame(frame);
  };
  const kick = () => {
    if (!raf) raf = requestAnimationFrame(frame);
  };
  const io = new IntersectionObserver(([e]) => {
    visible = e.isIntersecting;
    kick();
  });
  io.observe(host);
  document.addEventListener('visibilitychange', kick);

  document.fonts.ready.then(() => {
    paintText(identity);
    renderer.render(scene, camera);
    onReady();
    kick();
  });

  return {
    update(s, instant = reduced) {
      const d = instant ? 0 : 1;
      if (s.drift !== undefined) gsap.to(u.uDrift, { value: s.drift, duration: 0.9 * d, ease: 'power2.inOut', overwrite: true });
      if (s.clamp !== undefined) gsap.to(u.uClamp, { value: s.clamp, duration: 0.7 * d, ease: 'back.out(1.4)', overwrite: true });
      if (s.signals) gsap.to(u.uSig.value, { endArray: s.signals, duration: 0.4 * d, ease: 'power3.out', overwrite: true } as gsap.TweenVars);
      kick();
    },
    setIdentity(id) {
      paintText(id);
      kick();
    },
    dispose() {
      cancelAnimationFrame(raf);
      window.removeEventListener('pointermove', onMove);
      document.removeEventListener('visibilitychange', kick);
      io.disconnect();
      ro.disconnect();
      gsap.killTweensOf([u.uDrift, u.uClamp, u.uSig.value]);
      geo.dispose();
      face.dispose();
      edge.dispose();
      textTex.dispose();
      u.uVoid.value.dispose();
      renderer.dispose();
      renderer.domElement.remove();
    },
  };
}
