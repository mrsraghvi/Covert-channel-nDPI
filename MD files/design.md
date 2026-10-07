# Design — CovertScope UI/UX direction

## 1. Identity: "oscilloscope," not "admin template"

The design brief for this dashboard was to *not* look like a generic
Bootstrap/Tailwind admin template with a sidebar, some cards, and a
default chart library look. The chosen identity is **a signal-analysis
instrument** — the mental model is an oscilloscope/spectrum-analyzer bench
tool, because that's conceptually what this app does: it watches a signal
(network traffic) and flags anomalies in its shape.

The signature motif is a **scrolling waveform trace**
(`components/Waveform.jsx`) — reused in the topbar's live traffic ticker,
and available for any per-metric sparkline. One component, reused
everywhere a trend needs showing, rather than a different mini-chart style
per page. If you add a new trend visualization, reuse `Waveform` before
reaching for a new chart type.

## 2. Color system

Defined once in `theme.css` as CSS custom properties — never hardcode a
hex value in a component; reference the variable.

| Token | Hex | Use |
|---|---|---|
| `--bg` | `#0a0d13` | Page background — near-black, not pure black |
| `--panel` / `--panel-raised` | `#10141d` / `#141926` | Card surfaces, two elevation levels |
| `--hairline` / `--hairline-soft` | `#1f2532` / `#171c28` | Borders — subtle, not high-contrast dividers |
| `--text-primary` | `#e6e9f2` | Body text |
| `--text-secondary` | `#a8b0c3` | Labels, secondary info |
| `--text-muted` | `#788299` | Timestamps, de-emphasized metadata (see note below) |
| `--signal-cyan` | `#45d9c4` | Nominal/benign — the "everything's fine" color |
| `--signal-amber` | `#eba53f` | Medium confidence |
| `--signal-red` | `#ef5368` | Critical alerts, destructive actions (block) |
| `--signal-violet` | `#9b8cf0` | ML anomaly score specifically (kept visually distinct from the rule-based/statistical score, which uses cyan→amber→red) |

**`--text-muted` is WCAG-AA-checked, not eyeballed.** The original
`#626b81` only hit 3.3–3.65:1 contrast against the panel backgrounds it's
used on — below AA's 4.5:1 minimum for normal text. It was replaced with
`#788299` (same hue, more lightness), verified at 4.56:1+ against every
background it actually appears on. If you touch this token again, recompute
the contrast ratio against `--bg`, `--panel`, and `--panel-raised` before
committing to a value — don't just eyeball it against one background.

This is a **dark-mode-only** design. There is no light theme toggle; the
oscilloscope identity doesn't translate to a light background, and nothing
in the current design budget covers building and maintaining a second
palette.

## 3. Typography

Two families, both loaded from Google Fonts in `index.html`:
- **Inter** (`--font-sans`) — UI text, labels, body copy.
- **IBM Plex Mono** (`--font-mono`, applied via the `.mono` class) — every
  number, IP address, protocol name, hex value, threshold key, and anything
  else that benefits from tabular/monospace alignment. This is a deliberate
  split, not decoration: scanning a column of flow byte-counts or IP
  octets is meaningfully easier in a monospace, tabular-figure font.
  `.mono` also sets `font-variant-numeric: tabular-nums`.

Rule of thumb: if it's a sentence a human reads, Inter. If it's a value a
human scans/compares across rows, Plex Mono.

## 4. Component patterns

- **`.card`** — the one surface primitive (`background: var(--panel)`,
  1px hairline border, soft shadow). Every panel on every page is a
  `.card`; don't invent a second surface style.
- **Badges** (`ConfidenceBadge`, `ProtocolPill`, `BlockedBadge` in
  `Primitives.jsx`) — small, pill/rounded-rect, mono font, color-coded to
  the signal palette above. `BlockedBadge` specifically uses
  `--signal-red` since a block is a security-relevant, attention-worthy
  state — don't reuse amber/cyan for it even if visual balance tempts you.
- **Confirmation modals** (`ApiKeyGate`, `BlockConfirmModal`) — same visual
  shape: dark overlay with blur, centered card, explicit Cancel +
  colored-confirm button pair. Any new state-changing/security-relevant
  action (not just block) should reuse this shape rather than a bare
  `window.confirm()` or a silent one-click action.
- **Gauge** (`components/Gauge.jsx`) — half-circle arc gauge for a single
  bounded 0–1 metric (e.g. an alert's final score). Use this, not a new
  circular-progress component, when the data is a single ratio.
- **Focus states**: `.focus-ring:focus-visible` is applied to every
  interactive element (buttons, nav links, inputs) — this is the
  accessibility baseline for keyboard navigation. New interactive elements
  get this class.

## 5. Layout rules

- Sidebar + main content, flex row, `overflow: hidden` on the outer
  container so only `<main>` scrolls (`App.jsx`). Don't let the page body
  itself scroll — individual panels/tables manage their own overflow.
- Wide content (the Flows table) scrolls horizontally inside its own
  container (`overflowX: auto`), never forcing the whole page to scroll
  sideways.
- **Responsive breakpoint at 860px**: sidebar collapses from a fixed
  220px (with labels) to a 64px icon-only rail (`theme.css`, `.sidebar`
  rules). This is a CSS-only collapse (no JS state, no hamburger/drawer) —
  deliberately, to keep it simple for what's primarily a desktop/analyst
  tool that just shouldn't become unusable on a laptop-width window.
  Don't build a full mobile drawer pattern unless actual mobile usage
  becomes a real requirement, not just a nice-to-have.
- Route-level code splitting: everything except `Dashboard` (the landing
  page) is `React.lazy`-loaded (`App.jsx`). New pages follow this pattern.

## 6. Motion

`@media (prefers-reduced-motion: reduce)` is respected globally
(`theme.css` — collapses all animation/transition durations to ~0). Any
new animated component (a new waveform variant, a transition) must keep
working under this rule, not just skip testing it.

## 7. What this is not

- Not a generic SaaS dashboard template — no default Tailwind-admin-kit
  card shadows, no default chart-library color schemes (recharts is used,
  but always re-themed to the signal palette, never its defaults).
- Not optimized for a public marketing presence — no hero sections, no
  CTAs, no light mode. See `prd.md` §Scope for why those were deliberately
  not added when a general pre-launch checklist suggested them.
- Not a mobile-first design — responsive enough not to break, not designed
  mobile-first. The primary use case is an analyst at a desktop running
  this against a lab VM.
