# Architecture — CovertScope

## 1. System overview

```
┌─────────────────┐  JSON over TCP :9999   ┌──────────────────────────────┐
│  ndpi-engine/    │  (AUTH-secret gated)   │  backend/ (FastAPI)          │
│  covert_detector │ ─────────────────────▶ │  - IngestEngine              │
│  (C, libpcap +   │                        │  - StatisticalDetector (6.x) │
│   nDPI)          │                        │  - MLDetector (IsolationFst) │
│  live packet     │                        │  - AlertManager (combine)    │
│  capture, host-  │                        │  - REST API (/api/*)        │
│  network only    │                        │  - WebSocket (/ws)           │
└─────────────────┘                        └──────────────┬───────────────┘
                                                            │
┌─────────────────┐  loopback only, two     │              │ asyncpg
│  generator/      │  independent checks    │              ▼
│  generator.py    │ ───(127.0.0.1 traffic)─┘       ┌───────────────┐
│  synthetic covert│                                 │  Postgres 16  │
│  traffic for      │                                 │  flows/alerts │
│  self-test        │                                 │  thresholds   │
└─────────────────┘                                   │  blocked_ips  │
                                                        └───────────────┘
                     REST (X-API-Key) + WS (ticket)
┌──────────────────────────────────────────────────────────────────────┐
│  frontend/ (React + Vite, served by nginx in Docker)                  │
│  Dashboard / Flows / Alerts / Analysis / Control pages                │
│  demo mode (synthetic local data) when backend is unreachable         │
└──────────────────────────────────────────────────────────────────────┘
```

Four independently-runnable pieces:
1. **`ndpi-engine/`** — C, libpcap + nDPI. Does live packet capture and
   protocol classification, computes per-flow timing/entropy features,
   streams flow JSON to the backend. Requires root/CAP_NET_RAW — runs on
   the host, **not** in the Docker Compose stack (see `docker-compose.yml`
   comments for why and how to add it if you want it containerized).
2. **`generator/`** — Python, stdlib sockets only. Produces synthetic
   covert-pattern traffic (4 techniques) against loopback, for validating
   the detector catches what it should.
3. **`backend/`** — FastAPI + SQLAlchemy(async) + asyncpg. Owns the
   detection pipeline, the DB, the REST/WebSocket API, and all the
   security controls (see §Security below).
4. **`frontend/`** — React 18 + Vite + react-router v7 + recharts. Static
   build served by nginx in production; `npm run dev` for local work.

## 2. Backend internals

### Request flow for a live-captured flow
1. C engine → TCP :9999, line-based JSON, `AUTH <secret>` handshake first
   if `COVERTSCOPE_INGEST_SECRET` is set (`engine.py::tcp_ingest_server`).
2. `IngestEngine.ingest(raw_flow)` (`engine.py`):
   - `feature_extractor.extract_features()` → 21-dim `FlowFeatures`
     (timing: IAT mean/variance/CV/autocorrelation/bimodality;
     volumetrics: packet/byte rate; payload entropy; DNS-specific;
     HTTP-specific; ICMP-specific).
   - `StatisticalDetector.evaluate(features)` → rule-based score + specific
     `reasons` list, checked against the live-tunable `thresholds` table.
   - `MLDetector.score(features)` → an Isolation Forest anomaly score
     (`n_estimators=200`, `contamination` tunable, retrained in-memory —
     see §Known limitations).
   - `AlertManager.combine(stat_score, ml_score)` →
     `final_score = 0.6*stat + 0.4*ml` (`STAT_WEIGHT`/`ML_WEIGHT` in
     `alert_manager.py`), compared against `alert_threshold` (default 0.40,
     tunable via the `alert_score` key) → confidence tier
     (LOW/MEDIUM/HIGH/CRITICAL), with a per-flow cooldown to prevent
     repeat-alert spam on one noisy flow.
   - Flow + (if raised) Alert persisted to Postgres.
   - Both broadcast over the WebSocket to every connected dashboard.
3. If the flow's src/dst IP matches the in-memory `blocked_ips` cache
   (loaded from DB at startup, kept live via the block/unblock API), the
   flow is marked `blocked=True` so a re-offending source is visible
   immediately.

### Simulated mode
`simulator.py` generates synthetic flows directly (no C engine needed) for
demoing/dev without root or a real interface — same `IngestEngine.ingest()`
path, so it's not a separate code path from real capture.

### Data model (`database.py` / `database/schema.sql`)
- `flows` — one row per classified flow, all `FlowFeatures` fields plus
  `is_covert`, `anomaly_score`, `blocked`.
- `alerts` — one row per raised alert, FK to `flows`, confidence tier,
  human-readable `reason` + `recommendation`.
- `thresholds` — key/value, the live-tunable detection parameters (12
  keys — see `schemas.py::KNOWN_THRESHOLD_KEYS`, kept in sync with the
  seed rows here).
- `blocked_ips` — the soft/advisory blocklist (see §Blocklist below).
- **Defined but unused**: `capture_sessions`, `transmissions_log`,
  `v_protocol_distribution`, `v_alert_summary` — pre-existing schema, no
  current code path reads/writes them. See `tasks.md` if you want to wire
  these up (session-level capture stats, generator audit trail, or swap
  `get_stats()`'s ad-hoc queries for the views).

### API surface
All REST/WS routes require `X-API-Key` except `GET /api/health`. Full list
in `main.py`; grouped by purpose:
- **Read**: `GET /api/stats`, `/api/flows`, `/api/alerts`, `/api/thresholds`,
  `/api/blocklist`, `/api/report`.
- **Capture control**: `POST /api/capture/start` (rate-limited 10/min),
  `/api/capture/stop`.
- **Generator control**: `POST /api/generator/start` (rate-limited 5/min,
  target independently re-validated as loopback), `/api/generator/stop`.
- **Alerts**: `POST /api/alerts/{id}/ack`.
- **Blocklist**: `POST /api/blocklist` (rate-limited 30/min, upserts),
  `DELETE /api/blocklist/{ip}`.
- **Thresholds**: `PUT /api/thresholds` (whitelisted keys only, each
  routed to whichever detector component actually reads it — see
  `main.py::put_threshold`'s comment for the historical bug this fixed).
- **WS auth**: `POST /api/ws-ticket` mints a single-use 30s ticket so the
  durable API key never has to ride in a URL (browser WS can't set custom
  headers).
- **Live updates**: `WS /ws` — `flow`, `alert`, `blocklist` message types.

## 3. Blocklist — what it is and isn't

**CovertScope is a passive monitor. It is not inline on the network path.**
`POST /api/blocklist` does not drop a single packet. What it actually does:
1. Persists the IP + reason to `blocked_ips`.
2. Marks any future matching flow (`flows.blocked`) so a re-offending
   source is immediately visible in the UI instead of blending back in.
3. Exposes the list at `GET /api/blocklist` for a **separate, real
   enforcement point** (edge firewall, router ACL, WAF) to poll and apply.

This was a deliberate scope boundary, not an oversight: making it drop
real traffic would mean the backend container running `iptables`/`nftables`
as a subprocess, which needs root/`CAP_NET_ADMIN` — directly reversing the
non-root, read-only container hardening (see `SECURITY.md`), and adding a
real command-execution surface to a tool that otherwise has none. If real
enforcement is ever wanted: build it as a **separate, minimally-privileged
service** that polls `/api/blocklist` and applies/removes rules — don't
expand the main backend's privileges to do it.

## 4. Security (see `SECURITY.md` and `CODE_REVIEW.md` for full detail)

- API-key auth on every route except health; WS uses a short-lived
  single-use ticket instead of the raw key in the URL.
- CORS restricted to an explicit allowlist, no wildcard+credentials.
- Pydantic validation on every write: whitelisted enums, regex-constrained
  interface names, IP-literal validation on blocklist entries, independent
  loopback re-validation on the generator target.
- Rate limiting (in-memory, per-process) on every state-changing route.
- Flow-ingest socket (`:9999`) requires an `AUTH <secret>` handshake.
- Non-root, read-only-root-filesystem backend container; secrets sourced
  from `.env`, never hardcoded; `docker-compose up` fails fast if unset.
- Dependencies pinned to versions with zero known CVEs as of the last
  `pip-audit`/`npm audit` pass (re-run these periodically — see `tasks.md`).

## 5. Known limitations (be honest about these, don't paper over them)

- **No persisted ML model.** `MLDetector`'s Isolation Forest is refit
  in-memory on whatever flows have been seen this process lifetime —
  restarting the backend resets it. Fine for a lab session, not fine if
  you want stable scoring across restarts.
- **IPv4 only**, end to end (C parser, DB schema, frontend IP parsing all
  assume dotted-quad).
- **In-memory rate limiter and WS-ticket store** — correct for one backend
  process, won't coordinate across replicas if you ever scale horizontally.
- **Flow table in the C engine is a fixed 65536-entry hash table** with no
  idle-flow eviction; `flow_lookup_or_create` correctly returns `NULL` and
  the caller correctly drops the packet when full (verified, not a memory
  bug) — but a very high number of concurrent 5-tuples could make new
  flows silently untracked until others export. Noted, not fixed — see
  `CODE_REVIEW.md` for why.
- `capture_sessions`/`transmissions_log` tables unused — see §2 above.

## 6. Where things live (quick reference)

| Concern | File |
|---|---|
| Detection pipeline orchestration | `backend/app/engine.py` |
| Feature extraction | `detection/feature_extractor.py` |
| Rule-based scoring | `detection/statistical_detector.py` |
| ML scoring | `detection/ml_detector.py` |
| Score combination + alert raising | `detection/alert_manager.py` |
| API routes | `backend/app/main.py` |
| Auth/rate-limit/audit | `backend/app/security.py` |
| Request/response validation | `backend/app/schemas.py` |
| ORM models | `backend/app/database.py` |
| Raw DB bootstrap | `database/schema.sql` |
| Live packet capture + classification | `ndpi-engine/covert_channel_detector.c` |
| Synthetic covert traffic | `generator/generator.py` |
| Dashboard shell + routing | `frontend/src/App.jsx` |
| Live-data/WS/blocklist state | `frontend/src/hooks/useLiveData.js` |
| API client (key handling, ticket exchange) | `frontend/src/lib/api.js` |
