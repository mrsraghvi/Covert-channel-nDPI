# memory.md — Project context (CovertScope)

Single consolidated reference for anyone (human or AI) picking this project
up cold. Deeper detail lives in `prd.md`, `architecture.md`, `rules.md`,
`design.md`, `tasks.md`, `SECURITY.md`, `CODE_REVIEW.md` — this file is the
map to those, plus the cross-cutting facts (env vars, dependency versions,
bug history) that don't belong in any one of them alone. If something here
conflicts with one of those files, the more detailed file wins and this
file is stale — fix this file.

## 1. One-paragraph summary

CovertScope is a single-operator/small-team **lab research tool** that
detects covert network channels (timing, DNS tunneling, HTTP header
smuggling, ICMP payload channels) via nDPI protocol classification plus a
statistical+ML hybrid scorer, with a live React dashboard. It runs locally
or on an isolated VM (confirmed real deployment: Windows + WSL + Docker,
localhost-only — see `launch.md`), not as a public or multi-tenant service.
Full detail: `prd.md`.

## 2. System design / architecture

Four independently-runnable pieces — C capture engine, Python generator,
FastAPI backend, React frontend. Full diagram and data-flow walkthrough:
`architecture.md`. Key facts worth having loaded without opening that file:

- Detection scoring: `final_score = 0.6 * stat_score + 0.4 * ml_score`
  (`alert_manager.py::STAT_WEIGHT/ML_WEIGHT`), alert raised above
  `alert_threshold` (default 0.40, live-tunable via the `alert_score`
  threshold key).
- The C engine and the generator are **not** in `docker-compose.yml` —
  the C engine needs host networking + `CAP_NET_RAW`/`CAP_NET_ADMIN` for
  live capture (compose comments explain the containerization tradeoff);
  the generator is a standalone script.
- Simulated-capture mode (`simulator.py`) and real-capture mode both feed
  the same `IngestEngine.ingest()` path — not a parallel/divergent
  implementation.
- The blocklist feature is **advisory, not inline enforcement** — this is
  a deliberate, explicitly-documented scope boundary, not a limitation to
  apologize for. Don't add real `iptables`/`nftables` execution to the
  backend; see `architecture.md` §Blocklist and `rules.md` §1 for why, and
  what the correct alternative design is if real enforcement is ever
  wanted.

## 3. Databases

- Postgres 16, async SQLAlchemy + `asyncpg`. Engine created with
  `pool_pre_ping=True` (`database.py`); **pool size/overflow are left at
  SQLAlchemy's defaults (5 / 10)** — not explicitly tuned, no evidence yet
  that it needs to be for a single-operator lab workload. Revisit if this
  is ever run under real concurrent load.
- `DATABASE_URL` env var, with a **hardcoded local-dev-only fallback**
  (`postgresql+asyncpg://covertscope:covertscope@localhost:5432/covertscope`)
  if unset — this fallback is for running the backend directly against a
  Postgres you set up yourself with matching throwaway creds; it is *not*
  what `docker-compose.yml` uses (compose requires `POSTGRES_PASSWORD` to
  be set, no fallback, fails fast if missing). Don't confuse the two paths.
- Tables: `flows`, `alerts`, `thresholds`, `blocked_ips` — all actively
  read/written. **`capture_sessions`, `transmissions_log`, and two views
  (`v_protocol_distribution`, `v_alert_summary`) are defined in
  `schema.sql` but have zero code paths reading or writing them** —
  pre-existing from before this tool was hardened, never wired up. Backlog
  item in `tasks.md`; don't assume they're live just because they're in
  the schema.
- No migration tool. Schema changes require hand-editing both
  `database.py` (SQLAlchemy models, used by `create_all()` at startup —
  only creates missing tables, does **not** ALTER existing ones) and
  `database/schema.sql` (the Docker Postgres bootstrap via
  `docker-entrypoint-initdb.d`) and keeping them in sync manually. This has
  already drifted once (the unused tables above). Alembic is a tracked
  backlog item, not yet done.

## 4. Auth

- **One shared API key** (`COVERTSCOPE_API_KEY`), not per-user accounts —
  deliberate, for a single-operator/small-trusted-team tool. Checked via
  constant-time comparison (`security.py::require_api_key`,
  `hmac.compare_digest`).
- Required on every route except `GET /api/health`.
- If `COVERTSCOPE_API_KEY` is unset, the backend **generates a random
  ephemeral key at startup and logs it once** — convenient for zero-config
  local dev, actively bad for anything left running unattended.
  `docker-compose.yml` forces the issue (fails to start without it set).
- WebSocket auth has two paths: a single-use 30-second ticket
  (`POST /api/ws-ticket` → `?ticket=`, preferred, avoids a durable secret
  riding in a URL/browser-history/access-logs) or the raw key as `?key=`
  (fallback, for script/CLI use where that tradeoff is acceptable).
- No session/cookie-based anything — stateless header (or query-param
  ticket) auth throughout. No CSRF surface as a result (nothing relies on
  ambient cookie credentials).

## 5. APIs

Full route-by-route list: `architecture.md` §2 "API surface". Conventions:
- Every mutating endpoint has a Pydantic request model in `schemas.py`
  with real constraints (`Literal` enums, `Field` bounds, custom
  validators) — never a bare `dict`/`Any` body.
- Every mutating endpoint is rate-limited (see §6 below) and
  audit-logged (`security.py::audit()` — logs action, client IP, and
  relevant params, **never the API key itself**).
- Response models (`FlowOut`, `AlertOut`, `BlockOut`, `StatsOut`) are
  explicit — no passing raw ORM objects back as JSON (except where
  `response_model=list[BlockOut]` lets FastAPI serialize ORM instances
  through the declared schema, which is the supported/safe pattern, not an
  exception to this rule).

## 6. Security (see `SECURITY.md` + `CODE_REVIEW.md` for the full history)

- CORS: explicit allowlist (`CORS_ORIGINS` env var), `allow_credentials=False`.
- Security headers via FastAPI middleware (X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy) and nginx (adds CSP, disables server
  tokens).
- Flow-ingest socket (`:9999`, fed by the C engine) requires an
  `AUTH <secret>` handshake (`COVERTSCOPE_INGEST_SECRET`) before any JSON
  is parsed — stops arbitrary hosts from injecting fake flow records.
- Request body capped at 64KB (checks `Content-Length` — not airtight
  against a client lying about it or using chunked encoding without one;
  documented caveat, not silently assumed solid).
- Secrets: `.env` (gitignored, `.env.example` provided), never hardcoded.
  A stale hardcoded secret was once found sitting in `.git/objects` *despite
  zero commits ever being made* — `git add` writes blobs independent of
  commit history. If you ever see "no commits yet" and assume that means
  "nothing's in git yet," that assumption is wrong; check `git cat-file`.
- Backend container: non-root user, read-only root filesystem,
  `no-new-privileges`. Postgres not published to the host by default.
- Dependencies: audited clean (`pip-audit`/`npm audit`, zero known CVEs)
  as of the last pass — **this is a snapshot fact with a timestamp
  attached to it in `tasks.md`, not a standing guarantee.** Re-check
  before relying on it being still true.
- No XSS surface found on review: zero `dangerouslySetInnerHTML` in the
  frontend; attacker-influenced strings (DNS queries, HTTP hosts/UAs from
  real traffic) only ever render through plain JSX text nodes.

## 7. Rate limiting

- In-memory, per-process sliding window (`security.py::RateLimiter`),
  applied via `enforce_rate_limit(bucket, limit, window_s)` as a FastAPI
  dependency.
- Current limits: capture-start 10/min, generator-start 5/min, blocklist
  writes 30/min (both POST and DELETE). Not applied to read-only GET
  routes.
- **Does not coordinate across multiple backend processes/replicas.**
  Correct and sufficient for the single-process deployment this ships as;
  would need a shared backing store (Redis etc.) before horizontal
  scaling. Same caveat applies to the WS-ticket store
  (`security.py::_ws_tickets`).

## 8. Caching

**There is no caching layer in this project.** No Redis, no in-process
response cache, no CDN-fronted static assets beyond nginx's normal
behavior. Every `GET` route hits Postgres directly each time. This hasn't
been a problem at the scale this tool actually runs at (a lab capture
session, not sustained production traffic), so it hasn't been added
speculatively. If `GET /api/stats` or `/api/flows` ever becomes a
bottleneck, that's the place to look — not before there's evidence it's
needed.

## 9. Testing

- **No automated test suite committed to the repo.** Everything verified
  so far (auth/validation/rate-limiting behavior, the threshold-routing
  fix, the blocklist upsert logic, dependency-upgrade compatibility) was
  verified via ad-hoc scripts using FastAPI's `TestClient` and either a
  real local Postgres or a hand-built in-memory fake session when
  Postgres wasn't reachable — run once during development, not retained
  as a runnable suite. This is a real gap, not a stylistic choice;
  see `tasks.md`.
- When a fake DB session was used instead of real Postgres, that
  limitation was stated explicitly rather than presented as equivalent
  coverage — keep doing that if you're ever in the same position.
- Hard-won testing lesson, twice: **a 200/OK response is not sufficient
  evidence a fix worked.** Both the threshold-routing bug and the
  blocklist `active_only` filter were verified by checking the actual
  underlying state changed (`engine.alert_manager.alert_threshold`,
  the filtered result set), not just the HTTP status code.
- Frontend: no test runner configured (no Jest/Vitest/Playwright). "Did it
  build" (`npm run build`) and manual dev-server boot checks are the
  current bar. Real component/e2e tests are a gap, not yet in `tasks.md`
  explicitly — add them there if you pick this up.

## 10. CI/CD

**None exists.** No GitHub Actions / GitLab CI / any pipeline config
anywhere in the repo. Every check described in this document (dependency
audits, builds, the manual test scripts above) has been run by hand,
once, during development — none of it re-runs automatically on a future
change. This is the single highest-value piece of unfinished work if this
project continues to evolve: see `tasks.md` §"Worth doing" for the
proposed minimum pipeline (audit + build + test on every change, audits
also on a schedule).

## 11. Monitoring / observability

- **No metrics/APM/tracing.** No Prometheus, no structured logging
  pipeline, no error tracking (Sentry etc.). `logging.basicConfig(level=INFO)`
  in `main.py` plus `security.py::audit()` for security-relevant actions —
  everything goes to stdout, nothing is aggregated or alerted on.
- `GET /api/health` exists as a liveness probe (reports capture status,
  totals, timestamp) but nothing currently polls it automatically — no
  Docker healthcheck configured on the backend service in
  `docker-compose.yml` (Postgres has one; backend doesn't — worth adding,
  not yet done).
- For a single-operator lab tool this has been an acceptable gap; treat it
  as a real one the moment this runs unattended for any length of time or
  with more than one person depending on it.

## 12. Scaling

Built and verified for **one backend process, one Postgres instance,
localhost or a single lab VM.** Specific things that would need to change
before horizontal scaling, all already called out in context above rather
than repeated as a new claim:
- In-memory rate limiter (§7) and WS-ticket store (§4) → shared store.
- No connection pool tuning done yet (§3) → revisit under real load.
- No caching layer (§8) → add if/when a specific endpoint is shown to be
  a bottleneck.
- C engine's flow table is a fixed 65536-entry hash table with no
  eviction (`architecture.md` §5) — a visibility gap under very high
  concurrent flow counts, not a crash risk (verified: lookups correctly
  return `NULL`/drop the packet when full, don't corrupt memory).

None of this is "broken" — it's accurately scoped to the single-operator
lab use case in `prd.md`. Don't "fix" any of it preemptively without a
concrete reason this tool's actual usage changed.

## 13. Environment variables (reference)

| Variable | Required? | Purpose |
|---|---|---|
| `COVERTSCOPE_API_KEY` | Required in `docker-compose.yml`; auto-generated (ephemeral, logged once) if unset when run directly | API auth |
| `COVERTSCOPE_INGEST_SECRET` | Required in `docker-compose.yml`; warns and runs open if unset when run directly | Flow-ingest socket auth (backend + C engine, must match) |
| `DATABASE_URL` | Has a local-dev fallback; compose always sets it explicitly | Postgres connection string |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | Required in `docker-compose.yml` (no fallback, fails fast) | Postgres bootstrap creds |
| `CORS_ORIGINS` | Optional, has a sane localhost default | Comma-separated allowed browser origins |
| `COVERTSCOPE_INGEST_HOST` | Optional, defaults to `0.0.0.0` | Bind address for the flow-ingest socket |

Full `.env.example` is the source of truth if this table and it ever
disagree.

## 14. Dependency versions worth remembering

(Snapshot as of the last audit — check current `requirements.txt`/
`package.json` for ground truth, this is institutional memory of *why*
these versions, not a promise they're still current.)
- Backend was upgraded from `fastapi==0.115.0` (pulling in a `starlette`
  with 16 known CVEs between it and `python-multipart==0.0.9`) to
  `fastapi==0.141.1` / `starlette 1.6.0` / `python-multipart==0.0.32`.
  Full test suite re-run against the new stack before accepting the bump.
- Frontend was upgraded from `react-router-dom` v6→v7 and `vite` v5→v8 to
  clear 5 known vulnerabilities (`esbuild`, `nanoid`, `react-router`).
  Both major-version bumps were build-tested and dev-server-boot-tested
  before accepting them, since a major version bump is exactly where
  silent breakage likes to hide.

## 15. Notable bug history (why some rules in `rules.md` exist)

- **Threshold routing no-op**: `PUT /api/thresholds` for `alert_score` and
  `ml_contamination` silently did nothing for a while — it unconditionally
  wrote into `stat_detector.t[key]`, which neither of those two keys is
  ever read from. Found during code review, not by a user report. Fixed
  by routing each key to the component that actually reads it, and
  verified by checking the live object changed, not just the HTTP status.
- **Self-introduced whitelist regression**: when the threshold-key
  whitelist was first added (as a security fix, to stop arbitrary-key
  writes), it was scoped to the 7 keys the Control page's UI happened to
  expose at the time, not the full 12 keys `schema.sql` actually seeds —
  would have silently started rejecting valid updates to the other 5 the
  moment anything called them. Caught before shipping, by re-reading the
  schema rather than assuming the UI was a complete list.
- **Stale secret in git despite "no commits yet"**: see §6 above.
- **Fake-DB-session test gaps**: two separate times, a hand-built
  in-memory fake session (standing in for Postgres when it wasn't
  reachable) was initially *wrong* in a way that would have masked a real
  bug — once not modeling `UPDATE` rowcount based on whether a row
  actually matched (so a 404-on-not-found test passed even when the real
  logic was broken), once not handling a plain "select all" query. Both
  caught by the test itself failing unexpectedly, both fixed, both
  re-verified. Lesson generalized into `rules.md` §3.

## 16. Where to look first for...

| Question | Doc |
|---|---|
| "What is this for, who's it for" | `prd.md` |
| "How does data flow end to end" | `architecture.md` |
| "Can I do X, is it safe" | `rules.md` |
| "What should this look like" | `design.md` |
| "What's left to do" | `tasks.md` |
| "What's the actual threat model" | `SECURITY.md` |
| "What was found/fixed and why, in detail" | `CODE_REVIEW.md` |
| "How do I run this on my machine" | `README.md` (+ `launch.md` for the specific Windows/WSL/Docker setup this has actually been run under) |
