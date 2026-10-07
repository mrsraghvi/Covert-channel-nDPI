# CovertScope — nDPI Covert Channel Detection System

A research-grade platform for detecting covert network channels (timing
channels, DNS tunneling, HTTP header stuffing, ICMP payload abuse) using
**nDPI** for protocol classification, a hybrid **statistical + ML (Isolation
Forest)** detection engine, and a live multi-page dashboard.

Every layer described in the original design doc is implemented and has
been built/tested in this environment:

| Layer | Status | Notes |
|---|---|---|
| nDPI C engine (`ndpi-engine/`) | ✅ built & smoke-tested | Compiles against a real nDPI checkout; verified against a synthetic pcap — correctly classified a DNS flow and computed IAT/entropy stats, streamed as JSON over TCP :9999 |
| Detection engine (`detection/`) | ✅ built & tested | Statistical rules + Isolation Forest; verified against 200 synthetic flows (40 alerts raised, correct reasoning) |
| Backend (`backend/`) | ✅ built | FastAPI, Postgres via SQLAlchemy async, WebSocket broadcast, TCP ingest listener |
| Database (`database/schema.sql`) | ✅ built | Flows, alerts, thresholds, capture sessions, views |
| Dashboard (`frontend/`) | ✅ built & compiled | React + Recharts, 5 pages, production build passes |
| Test-traffic generator (`generator/`) | ✅ built & tested | **Hard-restricted to loopback** — see Security notes below |

---

## Architecture

```
┌────────────┐   TCP :9999 (JSON/line)   ┌──────────────────┐   Postgres    ┌──────────┐
│ nDPI C      │ ────────────────────────▶ │  FastAPI backend │ ────────────▶ │ Postgres │
│ engine      │                            │  + detectors     │               └──────────┘
│ (libpcap)   │                            │  + WebSocket     │
└────────────┘                            └────────┬─────────┘
                                                     │ WS :8000/ws + REST
                                                     ▼
                                            ┌──────────────────┐
                                            │ React dashboard  │
                                            │ (5 pages)        │
                                            └──────────────────┘
```

The dashboard works two ways:
- **Connected to the backend** (`npm run dev` with the API running): live flows/alerts stream over WebSocket.
- **Standalone / demo mode** (no backend reachable): falls back automatically to an in-browser synthetic traffic generator so every page, chart, and interaction is explorable immediately.

---

## Quick start

### 1. Detection engine (pure Python, no infra needed)
```bash
cd detection
python3 -c "
from feature_extractor import extract_features
from statistical_detector import StatisticalDetector
sd = StatisticalDetector()
# see the smoke test in project history for a full example
"
```

### 2. Full stack via Docker
```bash
cp .env.example .env   # fill in real secrets — see comments in the file
docker-compose up -d
# Dashboard: http://localhost:3000   (paste your COVERTSCOPE_API_KEY when prompted)
# API:       http://localhost:8000/docs
```

### 3. C nDPI engine (lab VM, real capture)
```bash
cd ndpi-engine
git clone --depth 1 https://github.com/ntop/nDPI.git nDPI-dev   # if not already present
make            # builds nDPI (if needed) + covert_detector
sudo COVERTSCOPE_INGEST_SECRET=<same value as backend's .env> ./covert_detector eth0 "not port 22"
```
This streams classified flow JSON to the backend on `127.0.0.1:9999`, authenticating
with `COVERTSCOPE_INGEST_SECRET` (must match the backend's env var of the same name).
Point `BACKEND_HOST`/`BACKEND_PORT` at a remote backend by editing the `#define`s
at the top of `covert_channel_detector.c` if the backend isn't local.

### 4. Frontend dev server (hot reload)
```bash
cd frontend
npm install
npm run dev      # http://localhost:3000, proxies /api and /ws to :8000
```

---

## Dashboard pages

- **Dashboard** — live stat cards, packet/anomaly timeline, covert-ratio & entropy gauges, protocol pie chart, recent alerts feed.
- **Flows** — full searchable/filterable flow table with per-flow anomaly score, a "BLOCKED" badge on any flow matching an active blocklist entry, and a per-row Block/Unblock action.
- **Alerts** — confidence-tiered alert cards (CRITICAL/HIGH/MEDIUM/LOW), expandable to show detection reasoning + remediation guidance, with acknowledge *and* block-source-IP actions (confirmation-gated).
- **Analysis** — covert-type bar chart, protocol radar (packets/bytes/duration), entropy histogram, IAT-vs-entropy anomaly scatter.
- **Control** — start/stop capture (simulated or live), replay authorized Ethernet PCAP/PCAPNG files offline, lab-only test generator (gated behind an explicit "I'm in my isolated lab VM" checkbox), live threshold tuning, an active-blocklist panel (raise/lift blocks, see who's blocked and why), JSON report export.

PCAP replay accepts files up to 25 MiB (100,000 packets and 5,000 directional
flows). It parses IPv4 and IPv6 packets, uses common service ports for basic
protocol labels, and sends extracted flows through the same statistical and
ML detectors as live ingest. It is an offline analysis path: it does not
transmit packets, and its protocol labels are heuristic rather than nDPI
classifications. Non-Ethernet captures and malformed or unsupported packets
are rejected or counted as skipped.

The whole UI follows one signature visual motif — a scrolling oscilloscope waveform (`components/Waveform.jsx`) — reused in the topbar traffic ticker, tying the "signal analysis" identity together instead of using generic dashboard-template styling.

### Taking action on an alert: the blocklist

Alerts and Flows both have a **Block** action for a flow's source IP. Read
this before you rely on it operationally:

**CovertScope is a passive monitor. It does not sit inline on the network
path, so blocking an IP here does not itself drop any packets.** What it
does:
1. Persists the IP to the `blocked_ips` table and flags any future flow
   from/to it — a re-offending source is immediately visible (a red
   "BLOCKED" badge) instead of blending back into the flow list.
2. Exposes the list at `GET /api/blocklist` for a real enforcement point —
   your edge firewall, router ACL, or WAF — to poll and actually apply.

We deliberately did not have the backend shell out to `iptables`/`nftables`
directly: that needs root/`CAP_NET_ADMIN`, which would undo the non-root,
read-only container hardening described in SECURITY.md, and it turns a
detection tool into an active-response one with a command-execution surface
to match. If you want real inline enforcement, the clean way to add it is a
small separate service (with the elevated privileges scoped to just that
service) that polls `/api/blocklist` and applies/removes rules — not a
change to the backend container.

---

## Security & research use

> ⚠️ **Research/authorized-testing use only.** Always get proper authorization before running packet capture or generating test traffic on any network, even your own.

- **API authentication.** Every route except `/api/health` requires an `X-API-Key` header (or `?key=` on the WebSocket), checked against `COVERTSCOPE_API_KEY`. The dashboard prompts for it at runtime and keeps it only in `sessionStorage` — it is never baked into the built JS.
- **The generator (`generator/generator.py`) is hard-restricted to loopback targets**, independently re-checked by the backend before it ever spawns the subprocess. It resolves and re-validates the target IP before sending anything and will refuse (exit code 2) on any non-loopback address — it's a detector self-test harness, not a general exfiltration/tunneling tool. The Control page also gates it behind an explicit lab-VM acknowledgment checkbox.
- The C engine performs **read-only packet inspection**: it does not inject, modify, or forward traffic. Its flow-ingest connection to the backend (`:9999`) is authenticated with a shared secret (`COVERTSCOPE_INGEST_SECRET`) to stop arbitrary hosts from injecting fake flow records.
- Live capture requires root/CAP_NET_RAW+CAP_NET_ADMIN, matching standard pcap tooling requirements (tcpdump, Wireshark, etc).
- All generator transmissions are logged to `generator/transmissions.jsonl`.
- Secrets (DB password, API key, ingest secret) are sourced from a gitignored `.env` — `docker-compose up` fails fast with a clear message if they're unset. See `.env.example`.
- Full threat model, residual risks, and a pre-deployment checklist: see **[SECURITY.md](SECURITY.md)**.
- Line-level code review with severity-rated findings: see **[CODE_REVIEW.md](CODE_REVIEW.md)**.

---

## What to extend next

- IPv6 support in the C engine (currently IPv4-only for the packet parser).
- Model persistence for the Isolation Forest (currently retrains in-memory each run).
- Alembic migrations instead of the raw `schema.sql` bootstrap.
- Per-user accounts / RBAC if you need more than one shared API key (see SECURITY.md).
- TLS termination via a reverse proxy for anything beyond localhost — see `docs/enforce-https.md` for ready-to-use Caddy/nginx configs.
