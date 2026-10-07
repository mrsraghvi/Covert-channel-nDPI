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
- [x] **Verify the blocklist upsert path against real Postgres.**
      `backend/tests/test_blocklist_postgres.py` verifies persistence,
      deactivation, reactivation/upsert, and active-only listing against a
      dedicated `covertscope_test` database. It is opt-in for local runs
      through `COVERTSCOPE_TEST_DATABASE_URL` and runs in CI against the
      Compose Postgres service.
- [x] **Alembic migrations.** Added an immutable bootstrap revision and a
      blocklist/threshold revision. Backend startup upgrades the database
      automatically; existing tables and rows are adopted without dropping
      data. Compose no longer relies on Postgres's first-volume-only
      `schema.sql` bootstrap. The real-Postgres integration test reruns
      migrations and verifies an existing blocklist row survives.
- [x] **Resolve the unused capture/generator tables and views.** They had
      no readers or writers, so they were removed from the fresh-schema
      bootstrap and migration. Existing database volumes are not dropped or
      rewritten; any legacy objects and their data remain untouched.
- [x] Re-run dependency vulnerability audits and automate them. `npm audit`
      reports zero advisories across the frontend lockfile; `pip-audit`
      reports no known vulnerabilities in the pinned backend requirements.
      Both audits now run on pushes, pull requests, manual dispatch, and a
      weekly schedule in GitHub Actions.
- [x] Add detector-coverage regression tests for the loopback generator's
      timing, DNS, HTTP, and ICMP signatures. The tests verify each default
      signature raises the matching rule alert and include a low-signal
      control case. The C engine now exports IAT bimodality, and the
      generator's default payload is long enough to exercise the HTTP rule.
      The API and frontend now use that same payload default rather than
      overriding it with shorter messages that miss the HTTP signature.
- [x] **IPv6 support through capture and display.** The live C parser tracks
      IPv4 and IPv6 flow keys, parses bounded IPv6 extension-header chains,
      and exports bracketed IPv6 endpoints. The backend endpoint parser and
      dashboard preserve the address correctly. Fragmented IPv6 packets
      requiring reassembly are skipped. A dual-stack offline PCAP verified
      the C engine export.

### Worth doing
- [x] CI pipeline runs dependency audits, backend tests, frontend tests
      and build, Docker Compose validation, container smoke tests, and the
      PostgreSQL integration test on pushes and pull requests. Dependency
      audits also run weekly.
- [x] Persist the Isolation Forest model, scaler, and training window
      across backend restarts. Compose stores the state in a dedicated
      named volume; unit tests cover round-trip restoration and safe startup
      when the model file is missing or corrupt.
- [ ] Validate all four generator signatures through live capture on the
      isolated Linux lab VM before deployment; unit tests and offline PCAP
      checks do not replace this privileged runtime check.
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
