# ThreatLens AI — Design System & Frontend Spec

This is the visual and interaction spec for **M11 Web Experience** (see [ARCHITECTURE.md](ARCHITECTURE.md)). Two surfaces share one design system:

- **Landing (`/`)**: a scroll-driven story where a judge watches an agent's identity break.
- **Console (`/console`)**: the working SOC tool used in the live demo.

---

## 1. The idea: an agent's identity is a security document

Every real identity document (passport, banknote, ID card) is protected by the same craft: **guilloche** line patterns, **holographic foil**, **UV-reactive ink**, **machine-readable zones**, and **tamper-evident seals** that show *VOID* when someone interferes.

ThreatLens borrows that whole visual language, because it maps exactly onto the problem:

| Security-printing feature | What it means in ThreatLens |
|---------------------------|-----------------------------|
| **Guilloche rosette** (unique, hard to forge) | An agent's **behavioral signature**. It is generated from the agent's Role Contract, so every agent's pattern is different. It has 9 concentric rings, one for each detection signal S0–S8. |
| **Holographic foil** | **Verified identity.** The foil shimmers while the agent behaves like its role. |
| **Tarnish → VOID pattern** (tamper tape) | **Drift.** As risk rises, the foil goes dull and a VOID pattern shows through. Credentials still look valid, but the seal is broken. |
| **UV lamp revealing invisible ink** | **Content forensics.** A UV lamp reveals the hidden prompt-injection text inside a PDF. |
| **Machine-readable zone (MRZ)** | Token ID, role version, and `jti` printed as a real MRZ strip on each Agent Passport. |
| **Rubber stamp** | Analyst decisions: *Approved*, *Isolated*, *Released* land as stamp impressions on the incident document. |

> **One-sentence pitch for the design:** *Agents carry passports. ThreatLens watches the hologram.*

### 1.1 What we rejected, and why

We tried the obvious directions first and threw them out because any "AI security" project could use them:

| Rejected | Why |
|----------|-----|
| Near-black background with neon orange/green "signal" accent | It's the default cyber look and says nothing about *identity*. |
| Seismograph/oscilloscope as the main metaphor | It fits "monitoring" in general, not "identity that stops matching". We kept a small drift chart in the console, but it isn't the brand. |
| Monospace small-caps labels everywhere, `01/02/03` numbered nav | That's template chrome. Monospace is now **only** for machine-readable strings (MRZ, token IDs, hashes), and numbering is **only** used where content is truly a sequence (the attack story, the containment tiers). |
| Glass cards, purple-blue gradients, glowing borders, bento grids | They're the most recognizable generated-UI tells. |
| Particle-sphere hero | It's impressive but means nothing. The passport hero *is* the product. |

---

## 2. Tokens

### 2.1 Color

Two grounds: **paper** (documents, landing) and **intaglio** (the console, deep engraving ink). Color carries meaning: shimmering foil means trusted, tarnish means drifting, void means compromised.

| Token | Hex | Role |
|-------|-----|------|
| `--paper` | `#DCE3DA` | Security-paper ground for the landing page, passports, and dossiers. Cool grey-green, deliberately *not* cream. |
| `--paper-ink` | `#1C3A3F` | Text and line work on paper |
| `--intaglio` | `#12262B` | Console ground (deep blue-green engraving ink) |
| `--intaglio-raised` | `#1A3238` | Raised console surfaces |
| `--guilloche` | `#8DB3AA` | Line work and secondary text on intaglio |
| `--foil` | shader (flat fallback `#B9C7E8`) | **Trusted.** Iridescent and view-angle dependent. Never used as a flat fill in the UI. |
| `--tarnish` | `#C9A23A` | **Drifting** (MONITOR, RESTRICT) |
| `--void` | `#C8323C` (text on dark: `#E5545D`) | **Compromised** (STEP-UP, ISOLATE), plus VOID patterns and the isolate stamp |
| `--uv` | `#7B5CFF` lamp light · `#E9F27A` fluorescent text | **Only** inside the UV forensics reveal |

**Tier encoding never relies on color alone.** Each tier also changes the **pattern** (foil → hatched tarnish → VOID text pattern) and has a text label.

| Tier | Color | Pattern | Seal state |
|------|-------|---------|------------|
| Allow | foil | clean guilloche | shimmering |
| Monitor | tarnish 40% | sparse hatch | dulling |
| Restrict | tarnish | dense hatch | dull, outer rings clamped |
| Step-up | void 60% | partial VOID | cracked |
| Isolate | void | full VOID | broken |

### 2.2 Type

| Family | License / source | Role |
|--------|------------------|------|
| **Archivo** (variable, width 62–125, weight 100–900) | OFL · Google Fonts / Fontsource | Everything readable. **Expanded width (115–125) at display sizes** gives the official-document voice. Normal width is for body and UI. One family, used at clearly different widths. |
| **OCR-B** (Matthew Skala's free digitization; fallback `Courier Prime`) | Free license · self-hosted | **Only** for machine-readable strings: MRZ strips, token IDs, hashes, raw tool calls. This is the passport MRZ typeface, so it's real vernacular, not decoration. |

**Scale** (ratio 1.25, base 16px): 13 · 16 · 20 · 25 · 31 · 39 · 49 · 61 · 76 · 95

- Body: 16–18px, leading 1.55, measure ≤ 72ch.
- Display: Archivo Expanded 700–800, tracking −1% to −2%, leading 1.0–1.05.
- Numbers in tables and risk values use `font-variant-numeric: tabular-nums`.
- **Sentence case everywhere.** No all-caps labels, no eyebrow text above headings, no single-word color/italic accents in headlines.

### 2.3 Shape, depth, texture

- **Radius follows the object, not a global token.** Documents (passport, dossier) use 14px, like a passport's rounded corners. Controls use 6px. Status chips are full pills. Data tables use 0.
- **Shadows only on physical documents** (passport, dossier, stamp), using a soft two-layer paper lift. UI panels have no shadow and are separated by tone (`--intaglio` vs `--intaglio-raised`).
- **Guilloche borders** frame **only** the passport and the dossier, never generic panels.
- **Paper grain:** a static 3% noise texture on `--paper` surfaces. No animated grain, no scanlines.

### 2.4 Layout

- Landing: a 12-column grid with a 1200px max width. Copy is **left-aligned**. Text columns max 6 of 12 columns, and the 3D passport uses the remaining width.
- Console: a fixed left rail of 232px, a top status strip of 52px, and a fluid main area. The minimum supported width is 1024px. Below that, the console shows a simplified single-column layout.
- Spacing scale (px): 4 · 8 · 12 · 16 · 24 · 32 · 48 · 64 · 96 · 128.

---

## 3. Signature element: the Agent Passport (three.js)

**This is where all the boldness goes. Everything around it stays quiet.**

The same `<AgentPassport agent={…} drift={0–100} />` component is used in the landing hero, on the Agents page, and in the incident dossier header.

### 3.1 Construction

| Layer | Technique |
|-------|-----------|
| Card body | `RoundedBox` (drei), paper material with grain normal map |
| **Guilloche rosette** | A fragment shader on a plane draws 9 rings as sums of epitrochoids, `r(θ) = R + Σ aₖ·sin(kθ + φₖ)`. The coefficients come from the agent's **role vector** (a hash of the Role Contract embedding), so each agent's pattern is deterministic and unique. Ring *i* = signal S*i*. |
| **Holographic foil** | A thin-film interference shader (view-angle → hue shift) masked to the seal area. It tilts with the pointer and device orientation. |
| **Drift** | A `uDrift` uniform (0–1) does three things: adds noise displacement to the rosette (the lines lose register, like a misprinted banknote); lowers foil saturation toward `--tarnish`; and raises a threshold mask that reveals a **VOID** text pattern. |
| **Per-signal emphasis** | A `uSignals[9]` uniform. A ring whose signal is firing thickens and shifts toward `--void`. This lets you *see* which signal caused the alert. |
| **Containment** | On RESTRICT, the outer rings (capabilities beyond the role) **clamp inward** (GSAP on ring radii) while the inner role rings stay intact. This is "scope snap-back" made visible. |
| Text | Agent name, role, and owner in Archivo. MRZ strip in OCR-B, rendered with `drei/Text` (troika). |

### 3.2 Performance rules

- The canvas is lazy-loaded, and the three.js chunk is code-split away from first paint. A static WebP poster shows until the WebGL scene is ready.
- DPR is clamped to `[1, 1.75]`. Rendering pauses when the passport is off-screen (`IntersectionObserver`) or the tab is hidden.
- Mobile (< 768px) or low-power devices (`navigator.hardwareConcurrency ≤ 4` or a failed WebGL2 check) get a pre-rendered loop video or poster.
- `prefers-reduced-motion`: no pointer tilt or idle animation. Drift changes are shown as instant state changes.

---

## 4. Motion system

**Rule: one orchestrated moment per surface. Every other motion answers something the user did.**

| Library | Used for |
|---------|----------|
| **GSAP** + ScrollTrigger | The landing's pinned hijack story (scrubbed by scroll) |
| GSAP **SplitText** | Hero headline reveal: the **one** load sequence, once |
| GSAP **ScrambleText** | The decoded hidden instruction resolving under the UV lamp |
| GSAP **Flip** | Opening an incident: the alert row expands into the full dossier |
| GSAP core | Passport uniforms (`uDrift`, ring clamps), the stamp landing |
| **Lenis** | Smooth scroll on the **landing only**. The console uses native scrolling in its panes, because smooth-scroll fights inner scroll areas and data tables. |
| `@gsap/react` (`useGSAP`) | Scoped animations with automatic cleanup in React |

Lenis + ScrollTrigger wiring (landing only):

```ts
const lenis = new Lenis({ lerp: 0.1 });
lenis.on('scroll', ScrollTrigger.update);
gsap.ticker.add((t) => lenis.raf(t * 1000));
gsap.ticker.lagSmoothing(0);
```

**Easing and timing**
- UI responses: `power3.out`, 180–260 ms.
- Document transitions (Flip, stamp): `expo.inOut` 500–700 ms. The stamp uses a short overshoot plus a 2px "ink spread".
- Drift on the passport: `uDrift` tweens over 900 ms with `power2.inOut`. Containment clamps use `back.out(1.4)`, so it feels like something snapped shut.

**Banned:** fade-and-slide-up on every section, hover lift on every card, looping ambient animations in the console, parallax on text.

`prefers-reduced-motion`: Lenis off, ScrollTrigger scenes become plain stacked sections with final states, ScrambleText shows the final text, and Flip becomes a crossfade.

---

## 5. Landing page (`/`)

Built on `--paper`. It reads like an official document that slowly gets compromised as you scroll.

```
┌──────────────────────────────────────────────────────────────┐
│ ThreatLens                               How it works  Console│
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Its token is valid.                      ╭──────────────╮   │
│  Its behavior isn't.                      │  ◎ rosette   │   │
│                                           │  (3D passport│   │
│  ThreatLens checks every action an        │   tilts with │   │
│  AI agent takes against the job it        │   pointer)   │   │
│  was created for, and steps in when       │ P<PROCUREMEN │   │
│  they stop matching.                      ╰──────────────╯   │
│                                                              │
│  [Watch an agent get hijacked]  Open the console             │
└──────────────────────────────────────────────────────────────┘
```

### Section plan

| # | Section | What happens |
|---|---------|--------------|
| — | **Hero** | Headline (SplitText reveal, the single load moment), a short paragraph, two actions. The passport tilts with the pointer and the foil shimmers. |
| 1–5 | **How a hijack looks from the inside** *(pinned and scroll-scrubbed. This is a real sequence, so the steps are numbered.)* | The passport stays pinned on the right while the left column steps through: **1** The procurement agent opens `supplier_quote.pdf`. **2** A UV lamp sweeps the PDF and the hidden instruction fluoresces, then the text resolves via ScrambleText. **3** The agent reads `/hr/salaries.xlsx`. A side column titled *What IAM sees* shows every check passing, while the passport rosette loses register and the foil tarnishes. **4** It tries to upload to `quote-verify.io`. The VOID pattern breaks through, and an *Isolated* stamp lands. **5** The outer rings clamp inward and the agent goes on creating a purchase request. *"Scope cut back to its role. Work continues."* |
| — | **Nine checks on every action** | The rosette is shown flat and large. Hovering or focusing a ring highlights it and shows that signal's plain-language question ("Does this action fit the agent's job?"). The rings *are* the list of signals, so there's no card grid. |
| 1–4 | **Contain the agent, keep the work** *(the tiers are an ordered scale, so they're numbered)* | Monitor → Restrict → Step-up → Isolate, as a vertical scale. Each tier shows what still works and what doesn't. |
| — | **Measured on 20,000 simulated actions** | Real numbers from `eval/results/latest.json`. If the file doesn't exist yet, the section reads *"Evaluation in progress"*. It never shows placeholder numbers. |
| — | **Close** | *"Agents carry passports. ThreatLens watches the hologram."* Button: **Open the console**. |

Copy rules: plain verbs, sentence case, the user's vocabulary ("the agent read salary files"), not system vocabulary ("S1 exceeded threshold"). Buttons say exactly what happens: **Run the PDF attack**, **Isolate agent**, **Release agent**, **Approve this change**.

---

## 6. Console (`/console`)

Built on `--intaglio`. Quiet, dense, and readable. The only "loud" things are the passports and the stamps.

```
┌───────────┬──────────────────────────────────────────────────────┐
│ ThreatLens│ Fleet seal: 4 of 4 intact   Gateway: warm   LLM: Groq ✓│
│           ├──────────────────────────────────────────────────────┤
│ Overview  │  Agents                         Drift, last 30 min   │
│ Agents    │  ┌ passport ┐┌ passport ┐       ╭──────────────────╮ │
│ Incidents │  │procurement││   hr     │      │ ~~~~~~~/\~~~~~~~ │ │
│ Approvals │  └──────────┘└──────────┘       ╰──────────────────╯ │
│ Simulate  │  ┌ passport ┐┌ passport ┐       Live actions          │
│ Forensics │  │ finance  ││ support  │       files.read /procur… │
│ Intel     │  └──────────┘└──────────┘       erp.create_pr  …    │
│ Arena     │                                                      │
│ Replay    │  Open incidents                                      │
│ Evaluation│  ▸ Procurement read HR salary data after a PDF…  93  │
└───────────┴──────────────────────────────────────────────────────┘
```

The nav is **not numbered**, because these pages are not a sequence.

| Page | What it shows | Interaction highlights |
|------|---------------|------------------------|
| **Overview** | Mini passports (2D canvas rosette, not WebGL, to keep it light), fleet drift chart, live action feed, open incidents | Clicking an incident opens the dossier with Flip. Keyboard: `g o` goes to Overview. |
| **Agents** | One full **3D passport** per selected agent. Role Contract next to observed behavior ("declared vs actual" resources), drift history, token lineage, active amendments | **Approve this change** turns observed behavior into a signed amendment |
| **Incidents** | **Incident Dossier** on `--paper`: plain-language headline, factor bars (each bar is labeled with its signal *and* its evidence), the hidden instruction (original next to decoded), causal timeline, counterfactual line, framework references, actions taken | Isolate / Release / Mark as harmless land as **stamps**. *Export report* downloads a PDF/Markdown dossier. |
| **Approvals** | Held STEP-UP actions: who, what resource, why it's held | Approve / Deny with a stamp. Keyboard `a` / `d`. |
| **Simulate** | Scenario launcher (A1–A6, B1–B2), each with *what to watch*. **Red Team Studio**: write a hidden instruction, pick techniques and a carrier, pick a target agent, launch it. | Number keys `1`–`8` fire scenarios during the demo |
| **Forensics** | **Content Forensics Lab**: paste or upload an email, URL, prompt, or PDF | A **UV lamp** follows the pointer over the document (WebGL shader) and hidden text fluoresces where the light falls. Scores are shown alongside, plus *which agents would be most at risk if they followed this*. |
| **Intel** | Fleet threat trend, injection signature feed, "known signature" hits (fleet immunity), top techniques and destinations | Clicking a signature lists every agent that read it |
| **Arena** | LLM Susceptibility Arena: one row per free model (Groq, Gemini, OpenRouter, Ollama). Shows whether it followed the hidden instruction, what it tried, and how fast. | **Run against all models** streams results live over WebSocket |
| **Replay** | Forensic time-travel: pick a session and scrub a timeline. The passport and scores rewind with it. | Scrubbing is the user's action, so motion follows it directly |
| **Evaluation** | Ablation table, per-scenario detection, false alerts per 1k actions, legit work preserved, latency | Read-only. Numbers come from `eval/results/latest.json` |

**Status strip** (always visible): fleet seal count, gateway state (*Warm* / *Waking up, about 30 s*), each LLM provider's status, and a ⌘K command palette (cmdk) for every action.

**Empty and error states give direction:**
- No incidents: *"No incidents. Run the PDF attack from Simulate to see one."*
- Gateway asleep: *"The gateway is waking up on Render's free tier. This takes about 30 seconds."* A slowly re-registering rosette shows progress.
- LLM provider rate-limited: *"Groq is rate-limited. Explanations are using Gemini."*

**Analyst login** (v1 auth layer, reused): email and password, then the Slider CAPTCHA. The slider track is a guilloche strip and the handle is a small seal. Its drag trajectory feeds the login-anomaly model. A blocked login says what happened and what to do: *"This sign-in looks unusual (new device at 3 a.m.). Ask an admin to approve it."*

---

## 7. Frontend stack

| Concern | Library |
|---------|---------|
| App | React 19 + Vite + TypeScript, React Router |
| Styling | Tailwind CSS v4 (tokens defined as CSS variables in `@theme`) |
| 3D | `three`, `@react-three/fiber`, `@react-three/drei`, `@react-three/postprocessing` (used sparingly: one subtle bloom on the foil only) |
| Motion | `gsap` (ScrollTrigger, SplitText, ScrambleText, Flip, CustomEase), `@gsap/react`, `lenis` |
| Data | `@tanstack/react-query` (REST), native `WebSocket` + `zustand` store for the live stream |
| Charts | `d3-scale` + `d3-shape` with hand-built SVG, so charts match the system instead of looking like a chart library's defaults |
| Graph | `d3-force` + SVG for the delegation graph (2D, because clarity matters more than spectacle here) |
| Command palette | `cmdk` |
| Icons | A small custom set drawn in the guilloche line style (seal, stamp, lamp, passport, chain). `@phosphor-icons/react` at *thin* weight as a fallback. |
| Fonts | `@fontsource-variable/archivo`, self-hosted OCR-B |
| Hosting | Vercel Hobby (static Vite build + SPA rewrite) |

GSAP and all its plugins (SplitText, ScrambleText, Flip, and the rest) are free to use, including commercially.

### Folder layout

```
web/
├── src/
│   ├── design/          # tokens.css, type.css, grain.webp
│   ├── three/           # AgentPassport, guilloche.frag, foil.frag, uvLamp.frag
│   ├── motion/          # lenis.ts, scroll scenes, stamp, flip helpers
│   ├── landing/         # Hero, HijackStory, SignalRosette, ContainmentScale, Results
│   ├── console/
│   │   ├── shell/       # Rail, StatusStrip, CommandPalette
│   │   ├── overview/ agents/ incidents/ approvals/ simulate/
│   │   ├── forensics/ intel/ arena/ replay/ evaluation/
│   │   └── auth/        # Login, SliderCaptcha
│   ├── api/             # REST client, WebSocket store, types generated from OpenAPI
│   └── main.tsx
└── public/posters/      # static fallbacks for 3D scenes
```

Types are generated from the FastAPI OpenAPI schema (`openapi-typescript`), so the frontend and backend share one contract.

---

## 8. Quality floor

- **Accessibility:** WCAG AA contrast on both grounds. Visible focus rings (a 2px `--foil`-fallback outline with offset). Every tier has a text label. The rosette rings are focusable buttons with an `aria-describedby` explanation. Stamps are announced through an `aria-live` region.
- **Responsive:** the landing works down to 360px wide. The console is designed for ≥ 1024px and degrades to a single column below that.
- **Performance budget:** landing LCP < 2.5 s on desktop, initial JS (without the 3D chunk) < 180 KB gzipped, Lighthouse performance ≥ 85 on desktop.
- **Squint test before every merge:** if a screenshot could belong to any other "AI security" product, it isn't done yet.
