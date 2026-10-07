# PRD — CovertScope

## 1. What this is

CovertScope is a research/lab tool that detects **covert channels** in
network traffic — timing channels, DNS tunneling, HTTP header smuggling,
ICMP payload channels — using nDPI-based deep packet inspection plus a
statistical + ML detection pipeline, surfaced through a live web dashboard.

It is **not** a product aimed at external customers. It's a single-operator
(or small trusted team) lab/research tool, run locally or on an isolated
VM, for studying covert-channel detection techniques and validating a
detector against known-bad traffic.

## 2. Problem statement

Covert channels — data smuggled inside legitimate-looking traffic (DNS
queries, HTTP headers, ICMP payloads, or just the *timing* between packets)
— are hard to detect with signature-based tools because there's no
malicious payload signature to match; the channel is the anomaly, not the
content. Someone studying or defending against this needs:
- A way to classify traffic by protocol and compute the statistical
  features (entropy, inter-arrival-time regularity, label length/entropy)
  that actually distinguish covert use of a protocol from normal use.
- A safe way to generate known-covert traffic to validate the detector
  actually catches what it claims to.
- A live view of what's being flagged, how confident the detector is, and
  a way to act on a flagged source.

## 3. Who this is for

- Security researchers studying covert-channel detection techniques.
- Students/academics in a network security course needing a hands-on
  detector to instrument and extend.
- A red/blue team lab exercise: one side generates covert traffic
  (loopback-only, see below), the other tunes the detector against it.

Not for: production network defense at scale, multi-tenant SaaS use,
unauthorized monitoring of traffic you don't have explicit permission to
capture.

## 4. Core user stories

- *As a researcher*, I start a capture session (simulated or live) and see
  classified flows stream in, so I can see the detector working in
  real time.
- *As a researcher*, I generate synthetic covert traffic against loopback
  and watch the detector flag it, so I can validate detection coverage per
  technique (timing / DNS / HTTP / ICMP).
- *As an analyst*, I see a ranked list of alerts by confidence
  (LOW/MEDIUM/HIGH/CRITICAL) with the specific statistical reason each one
  fired, so I can tell a real anomaly from noise.
- *As an analyst*, when an alert looks like a genuine re-offender, I raise
  a block on its source IP so future traffic from it is immediately
  flagged, and so a real firewall/edge device downstream can enforce it.
- *As a tuner*, I adjust detection thresholds (entropy cutoffs, IAT
  regularity, DNS label length, the ML contamination rate) live and see the
  effect on the next flows without restarting anything.
- *As anyone*, I can export a JSON report of what's been seen and flagged
  in this session.

## 5. Scope

### In scope (built)
- nDPI-based protocol classification (C engine, `ndpi-engine/`).
- Statistical + ML (Isolation Forest) hybrid scoring
  (`detection/`), weighted 60/40 stat/ML, combined into one `final_score`.
- Four alert confidence tiers, cooldown per flow to avoid alert spam.
- Loopback-only synthetic covert-traffic generator for validating
  detection coverage (`generator/`), independently validated as
  loopback-only in two places (its own check + the backend's).
- Live dashboard: Dashboard/Flows/Alerts/Analysis/Control pages, WebSocket
  live updates, demo mode when no backend is reachable.
- Soft/advisory IP blocklist (not inline enforcement — see
  `architecture.md` §Blocklist).
- API-key auth, rate limiting, input validation, audit logging — see
  `SECURITY.md`.

### Explicitly out of scope (by design, not oversight)
- **Real inline packet blocking.** CovertScope classifies traffic; it does
  not sit on the network path. See `architecture.md` for why, and what to
  build instead if you need real enforcement.
- **Multi-tenant / per-user accounts.** One shared API key, by design, for
  a single operator or small trusted team.
- **Public-facing deployment concerns** (privacy policy, cookie consent,
  SEO, analytics) — this is a private tool behind an API key, not a public
  site. See the chat history / `CODE_REVIEW.md` for the explicit reasoning
  on each skipped item.

### Known gaps / not yet wired up
- `database/schema.sql` defines `capture_sessions` and `transmissions_log`
  tables and two convenience views (`v_protocol_distribution`,
  `v_alert_summary`) that **no Python code currently reads or writes** —
  pre-existing schema from before this tool was hardened, never connected.
  See `tasks.md`.
- IPv6 is not supported end-to-end (the C engine's packet parser is
  IPv4-only).
- No persisted ML model — `MLDetector` retrains in-memory each process
  start (see `architecture.md` §Detection pipeline).

## 6. Success criteria

There's no external customer metric here — success is measured against
the tool's own purpose:
- All four covert techniques (timing, DNS, HTTP, ICMP) the generator can
  produce are reliably flagged by the detector at default thresholds.
- An operator can tell *why* something was flagged (the `reason` field
  on an alert is specific, not "anomaly detected").
- The dashboard stays usable and honest when the backend is unreachable
  (demo mode, not a broken blank page).
- Security posture holds up to the standard documented in `SECURITY.md`
  and `CODE_REVIEW.md` — no known unauthenticated state-changing routes,
  no secrets in the repo, no known CVEs in pinned dependencies.
