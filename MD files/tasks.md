# Tasks & progress — CovertScope

Status as of this document's creation. Update this file in the same change
that completes/adds a task — don't let it drift from reality.

## Done

### Security hardening (first pass)
- [x] API-key auth on every route except `/api/health`.
- [x] CORS locked to an explicit origin allowlist, `allow_credentials=False`.
- [x] Rate limiting on capture/generator/blocklist write routes.
- [x] Pydantic validation: `Literal` enums, regex-constrained interface
      names, bounded numeric fields, threshold-key whitelist.
- [x] Generator target independently re-validated as loopback on the
      backend (on top of `generator.py`'s own check).
- [x] Flow-ingest socket (`:9999`) `AUTH <secret>` handshake (both Python
      side and the C engine), line/buffer size caps.
- [x] Secrets moved to `.env` (gitignored), `docker-compose up` fails fast
      if unset — no more hardcoded DB password.
- [x] Backend container: non-root user, read-only root filesystem,
      `no-new-privileges`.
- [x] Security headers (API middleware + nginx: CSP, X-Frame-Options,
      X-Content-Type-Options, Referrer-Policy).
- [x] `SECURITY.md` written (threat model, residual risks, pre-deployment
      checklist).

### Security hardening (second pass / code review)
- [x] Purged a stale hardcoded secret that had been written into
      `.git/objects` by a prior `git add`, despite zero commits existing.
- [x] Dependency CVE audit: `pip-audit` found 16 known vulns
      (`starlette`/`python-multipart`), `npm audit` found 5
      (`esbuild`/`vite`/`nanoid`/`react-router`). Upgraded both stacks,
      re-ran the full test suite against the new versions. Zero known
      vulnerabilities as of the last audit — **re-run both audits
      periodically; this is a snapshot, not a permanent state.**
- [x] WS auth hardened: single-use 30s ticket exchange
      (`POST /api/ws-ticket`) instead of the raw API key riding in the
      WebSocket URL.
- [x] Request body size cap (64KB) against oversized-payload DoS — noted
      caveat: checks `Content-Length`, not a true streaming limit.
- [x] Fixed a real pre-existing bug: `alert_score`/`ml_contamination`
      threshold updates were silently no-ops (wrong dict). Fixed the
      routing, verified the live attribute actually changes.
- [x] Fixed a bug introduced during hardening: the first-pass threshold
      whitelist only had 7 of the real 12 keys. Expanded to match
      `schema.sql`.
- [x] `CODE_REVIEW.md` written with severity-rated findings.

### Feature: blocklist / take-action-on-alert
- [x] `blocked_ips` table + `flows.blocked` flag.
- [x] `GET/POST /api/blocklist`, `DELETE /api/blocklist/{ip}`, live WS
      broadcast on block/unblock.
- [x] `AlertOut` extended with `src_ip`/`dst_ip` (joined from `Flow`) so
      the frontend can act on an alert without a second round-trip.
- [x] Frontend: Block/Unblock actions on Alerts and Flows pages (behind a
      confirmation modal), active-blocklist panel on Control.
- [x] Explicit scope documentation: this is advisory, not real packet
      enforcement — see `architecture.md` §Blocklist.

### Pre-launch checklist pass
- [x] WCAG contrast fix on `--text-muted` (was ~3.3–3.65:1, now 4.56:1+).
- [x] Responsive sidebar collapse under 860px.
- [x] Custom 404 page + catch-all route.
- [x] Favicon (inline SVG), meta description, `noindex` robots meta.
- [x] Client-side interface-name validation on the Control page (matches
      backend regex, inline error + disabled button instead of a 422
      round-trip).
- [x] Route-level code splitting (`React.lazy`) — Analysis/Control/
      Alerts/Flows/NotFound no longer in the initial bundle.
- [x] `docs/enforce-https.md` — working Caddy/nginx+certbot configs.
- [x] Audited and confirmed N/A (not silently skipped): broken links
      (none found), image alt text/compression (zero `<img>` tags exist).
- [x] Explicitly skipped, with reasoning recorded: privacy policy, ToS,
      cookie consent, social preview image, sitemap/robots.txt, spam
      protection, analytics — see `prd.md` §Scope.

## Backlog / not yet done

Roughly ordered by "would catch a real problem" first.

### Should do soon
- [ ] **Verify the blocklist upsert path against real Postgres.** It was
      only tested against a hand-built in-memory fake session (local
      Postgres wasn't reachable during that work — stale apt mirror). The
      fake was built incrementally and got two things wrong on the way
      (UPDATE rowcount semantics, SELECT-all semantics) before being
      fixed — a real integration test would close this out properly.
- [ ] **Alembic migrations.** Schema changes currently mean editing both
      `database.py` (SQLAlchemy models, used by `create_all` at startup)
      and `database/schema.sql` (the Docker Postgres bootstrap) by hand
      and keeping them in sync. This already drifted once (see "unused
      tables" below) — a migration tool would catch drift and support
      upgrading an existing DB volume instead of requiring a fresh one.
- [ ] **Decide what to do with `capture_sessions`/`transmissions_log` and
      the two unused views.** Either wire them up (session-level capture
      stats, a real generator audit trail, swap `get_stats()`'s ad-hoc
      queries for the views) or remove them from `schema.sql` so the
      schema doesn't claim functionality that doesn't exist.
- [ ] Re-run `pip-audit`/`npm audit` — they were clean as of the last
      pass, but that's a point-in-time fact, not a standing guarantee.
      CI running these on a schedule (see below) would make this
      automatic instead of relying on remembering.

### Worth doing
- [ ] CI pipeline: `pip-audit` + `npm audit` on a schedule, backend
      `py_compile` + test suite, frontend `npm run build`, on every PR at
      minimum. None of this currently runs automatically — every check in
      this project so far has been manual, one-off verification.
- [ ] Persist the ML model (`MLDetector`) instead of refitting in-memory
      each process start, if stable scoring across restarts matters for
      your use case.
- [ ] IPv6 support in the C packet parser (currently IPv4-only end to
      end — parser, schema, frontend IP splitting all assume dotted-quad).
- [ ] If this is ever deployed beyond a single operator: real per-user
      auth (not the shared API key), and a shared rate-limiter/WS-ticket
      store (Redis or similar) instead of the current in-memory ones,
      which don't coordinate across multiple backend replicas.
- [ ] Idle-flow eviction in the C engine's flow table (currently a fixed
      65536-entry table with no eviction — not a memory-safety bug, see
      `architecture.md`, but a visibility gap under very high concurrent
      flow counts).

### If real inline enforcement is ever wanted
- [ ] Design + build a **separate, minimally-privileged service** that
      polls `GET /api/blocklist` and applies/removes real firewall rules.
      Do not add this capability to the main backend container — see
      `rules.md` §1 and `architecture.md` §Blocklist for why.

### Low priority / only if it becomes a real need
- [ ] A true mobile drawer-pattern sidebar (current fix is a CSS-only
      icon-rail collapse — fine until actual mobile usage is a
      requirement, not before).
- [ ] Further bundle-size reduction beyond route-level code splitting
      (e.g. splitting `recharts` itself out of the Dashboard's critical
      path) — only worth it if load time on the landing page becomes an
      actual complaint, not preemptively.
