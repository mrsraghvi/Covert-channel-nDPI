# Code review — CovertScope

Scope: full repo (backend, frontend, C nDPI engine, detection modules, generator,
Docker/infra). This covers both the hardening pass and a line-level review
looking for bugs and residual risk, not just the changes I made.

No system is "unhackable" — this documents what's addressed, what's
genuinely lower-risk now, and what's still open, so you know what you're
actually running.

## Findings

Severity is about impact if exploited, not likelihood. 🔴 High 🟠 Medium 🟡 Low ⚪ Info

### 🔴 Unauthenticated API + wide-open CORS (fixed)
Every route (`capture/start`, `generator/start`, threshold writes, flow/alert
reads) had no auth at all, and CORS was `*`. Anyone who could reach the port
had full control. **Fixed**: `X-API-Key` required on all routes except
`/api/health`; CORS restricted to an explicit origin allowlist,
`allow_credentials=False`.

### 🔴 Unauthenticated flow-ingest socket, `:9999` (fixed)
The TCP listener that receives flow records from the C engine accepted
anything from anyone — a spoofed record could poison the detector or DB, or
just flood it. **Fixed**: `AUTH <secret>` handshake required before any JSON
is parsed, both in `engine.py` and the C client. Buffer/line-size caps added
against memory-exhaustion DoS on that same socket.

### 🔴 Hardcoded DB credentials in `docker-compose.yml` (fixed)
`POSTGRES_PASSWORD: covertscope` in plaintext, committable as-is. **Fixed**:
sourced from `.env` (gitignored), compose now fails fast with a clear message
if secrets are unset.

### 🔴 That same secret was already sitting in `.git/objects` (fixed)
Non-obvious one: `git status` showed "No commits yet," but `git add` had
already been run, and Git writes blobs to the object database at `add` time,
independent of whether anything is ever committed. The old `docker-compose.yml`
content — including the hardcoded password — was already a retrievable blob.
**Fixed**: wiped and reinitialized `.git` (safe here specifically because
there was no commit history to lose — don't do this on a repo you care about
the history of; use `git filter-repo` or the BFG instead).

### 🟠 Known CVEs in pinned dependencies (fixed)
`pip-audit` found 16 known vulnerabilities: `starlette==0.38.6` (pulled in by
`fastapi==0.115.0`) had several, `python-multipart==0.0.9` had several more.
`npm audit` found 5 in the frontend (`esbuild`/`vite`, `nanoid`,
`react-router`). **Fixed**: upgraded to `fastapi==0.141.1` (→ starlette
1.6.0), `python-multipart==0.0.32`, `react-router-dom@7`, `vite@8`. Re-ran
the full detection pipeline and API test suite against the new backend stack,
and rebuilt the frontend twice — no breakage. `pip-audit`/`npm audit` both
now report zero vulnerabilities in runtime dependencies.

### 🟠 API key exposed via WebSocket URL (fixed)
Browsers can't set custom headers on a WS handshake, so the key had to travel
some other way — as `?key=...` it wound up in browser history and would show
up in any access/proxy logs along the request path. **Fixed**: added
`POST /api/ws-ticket` (itself behind the normal API-key check) that mints a
random, single-use, 30-second ticket; the frontend exchanges the key for a
ticket before opening the socket. Raw-key-in-URL still works as a fallback
for scripts/CLI use, where that trade-off may be acceptable. Verified: valid
ticket connects once, a reused or garbage ticket is rejected, unauthenticated
connections are rejected.

### 🟠 Threshold update silently broken for 2 of 12 keys (fixed, pre-existing bug)
`PUT /api/thresholds` unconditionally wrote every key into
`stat_detector.t[key]`. Two of the twelve threshold keys the DB seeds —
`alert_score` and `ml_contamination` — aren't read from that dict at all;
they belong to `alert_manager.alert_threshold` and `ml_detector.contamination`
respectively. Moving either slider in the Control page changed nothing.
**Fixed**: routed each key to the component that actually reads it, and
confirmed with a test that the real attributes change now.

### 🟠 Unrestricted input on capture/generator/threshold endpoints (fixed)
No validation on `interface` (free text, technically not exec'd anywhere
but unconstrained), `technique`/`mode` (any string accepted), threshold
`key` (arbitrary string → arbitrary row insert), generator `target` (backend
trusted `generator.py`'s own loopback check as the only guard — one layer,
not two). **Fixed**: `Literal` enums, regex-constrained interface names,
a threshold-key whitelist (now correctly covering all 12 real keys, see
below), and independent backend-side loopback validation on top of
`generator.py`'s own check.

### 🟡 My first-pass threshold whitelist was incomplete (self-caught, fixed)
When I added the whitelist above, I based it on the 7 keys the Control page
currently exposes sliders for, not the 12 keys `database/schema.sql` actually
seeds. That would have silently rejected legitimate updates to `dns_qps`,
`iat_autocorr`, `http_url_entropy`, and `icmp_payload_len` the moment anyone
called those. **Fixed**: expanded to match the schema.

### 🟡 No request body size limit (fixed, partial)
Nothing stopped an oversized JSON body from being buffered/parsed.
**Fixed**: 64KB cap via middleware, checked against `Content-Length`. Caveat:
this doesn't catch a client that lies about `Content-Length` or uses chunked
transfer encoding without one — real protection would need a streaming
read-with-limit at the ASGI layer. Given every real payload here is a
handful of short fields, low-risk to leave as the simpler check for now, but
worth knowing.

### 🟡 Containers running as root / no filesystem restrictions (fixed)
Backend Dockerfile had no `USER` directive. **Fixed**: non-root user,
`read_only` root filesystem + tmpfs `/tmp`, `no-new-privileges`, Postgres no
longer published to the host by default.

### 🟡 Missing security headers (fixed)
No CSP, X-Frame-Options, etc. on either the API or the static frontend.
**Fixed**: added to both (`main.py` middleware, `nginx.conf`).

### ⚪ nginx master process still starts as root
Standard behavior for the official `nginx:alpine` image — it binds the
socket as root, then workers drop to the `nginx` user. Not fixed; switch to
an unprivileged nginx image (e.g. `nginxinc/nginx-unprivileged`) if you want
to remove this entirely.

### ⚪ In-memory rate limiter and WS-ticket store are per-process
Fine for the single-backend-process deployment this ships as. If you scale
to multiple replicas, both need a shared backing store (Redis, etc.) — the
current implementation won't coordinate across processes.

### ⚪ Flow table exhaustion in the C engine is possible, by design tradeoff
`MAX_FLOWS` is a fixed 65536-entry hash table; `flow_lookup_or_create`
correctly returns `NULL` on a full table rather than corrupting memory, and
the caller correctly drops the packet in that case (checked this — no bug).
But nothing currently evicts idle/completed flows early, so a very high
number of concurrent 5-tuples could fill the table and cause new legitimate
flows to be silently un-tracked until existing ones export. This is a
visibility/availability characteristic of the current design, not a memory
safety bug — didn't change it, since retrofitting eviction logic under a
hardening pass risks introducing new bugs for a scenario (65k *concurrent*
flows on a lab capture point) that's a stretch for the stated use case.
Worth a deliberate look if you deploy this somewhere with real production
traffic volumes.

### ⚪ No XSS surface found
Checked every place flow/alert fields (`dns_query`, `http_host`, UA strings —
all attacker-influenceable via real network traffic) get rendered. No
`dangerouslySetInnerHTML` anywhere in the frontend; everything goes through
plain JSX text nodes, which React escapes automatically. Nothing to fix here,
documenting that I checked.

### ⚪ C parser bounds-checking
Reviewed the packet-parsing path (payload sampling, IAT sample array,
IP/L4 length arithmetic, flow-table indexing) for the classic C
vulnerability shapes — buffer overflow, integer underflow/wraparound,
out-of-bounds array access. Found `snprintf`/bounded `memcpy` used
throughout, explicit underflow guards on every length subtraction
(`(l4_len > data_off) ? l4_len - data_off : 0` pattern), and safe modulo-
bounded flow-table probing. No `strcpy`/`strcat`/`gets`/`sprintf` anywhere.
This is a read-through review, not a fuzzing campaign — if this engine will
ever face untrusted/adversarial pcap input beyond a lab network, running it
under AFL++ or libFuzzer against varied pcap samples first is good practice
for any C packet parser, malicious traffic included.

### ⚪ Single shared API key, not per-user
By design for a single-operator/small-team lab tool — see SECURITY.md. If
you need per-user identity or audit trails tied to a person rather than an
IP, that's a real auth system, not a header check.

## Feature added since the last review: blocklist / take-action

Added `blocked_ips` table, `flows.blocked` flag, `GET/POST /api/blocklist`
and `DELETE /api/blocklist/{ip}`, live WS broadcast on block/unblock, and
frontend Block/Unblock actions on Alerts, Flows, and a new Control panel.

**Scope decision, made explicitly rather than assumed**: this is a soft/
advisory block, not real packet-level enforcement. CovertScope is a passive
monitor with no inline network position, so making "block" actually drop
traffic would mean the backend executing `iptables`/`nftables` as a
subprocess — which needs root/`CAP_NET_ADMIN` in the container, directly
reversing the non-root + read-only hardening from the first pass, and adds
a real command-execution surface to a tool that previously had none. Kept
the advisory model (flag + exportable feed for a real enforcement point to
consume) instead. See README's "Taking action on an alert" section.

Applied the same validation discipline as the rest of the API: `ip` is
parsed with `ipaddress.ip_address()` before it touches a DB row or an
in-memory dict key (no hostnames, no injection surface), `reason` is
control-character-filtered, and the write endpoints sit behind the same
auth + rate-limiting pattern as capture/generator start.

**Testing note**: local Postgres wasn't available this round (apt mirror
had a stale package index I couldn't refresh — not something fixable from
inside this environment), so the blocklist endpoints were verified against
a hand-written in-memory fake session rather than a real database. The fake
was built incrementally and got two things wrong on the first pass (it
didn't model UPDATE `rowcount` based on whether a row actually matched, and
it didn't handle a plain "select all" query, only ip-keyed lookups) — both
caught by tests failing, both fixed, both confirmed passing after the fix.
Logic that's independent of real SQL semantics (the pydantic IP validation,
the in-memory `IngestEngine.block_ip`/`is_blocked`/`unblock_ip` methods, and
`ingest()` correctly setting `flow.blocked`) was exercised directly and
isn't subject to that caveat. Recommend a real integration test against
Postgres before relying on the upsert-on-reblock behavior in production.

## Pre-launch checklist pass (applied what fits a private lab tool, skipped what doesn't)

A generic website pre-launch checklist was requested. Several items
assume a public, SEO-indexed, form-collecting marketing site — this is a
private, API-key-gated dashboard (confirmed by `launch.md`: Windows/WSL/
Docker, localhost-only). Applying those anyway would add attack surface or
be actively wrong, not just unnecessary:

- **Skipped, with reasoning**: privacy policy / terms & conditions (no
  public users, no data collection from third parties), cookie consent
  banner (no cookies or tracking — `sessionStorage` isn't a cookie and
  nothing third-party reads it), social preview image / sitemap / robots.txt
  (not meant to be found or shared — added `<meta name="robots"
  content="noindex, nofollow">` instead, which is the *correct* opposite of
  what the checklist item assumed), spam protection (no public-facing forms
  accepting arbitrary internet submissions), analytics (adding third-party
  tracking to a defensive security tool is a privacy/surface regression, not
  an improvement), single clear CTA (multi-page operational tool, not a
  landing page).
- **Applied — genuinely fit**:
  - WCAG contrast fix: `--text-muted` only hit ~3.3–3.65:1 against the
    panel backgrounds it's used on (fails AA's 4.5:1 for normal text).
    Computed the actual luminance ratios, found a same-hue shade
    (`#788299`) that clears 4.5:1+ everywhere it's used, verified by
    recomputing after the change.
  - Mobile/narrow-viewport responsiveness: the sidebar was a fixed 220px
    with no breakpoint — now collapses to a 64px icon rail under 860px via
    CSS, no JS state needed. Tables already scrolled horizontally on their
    own (checked before claiming this was "fixed").
  - Custom 404 page + catch-all route.
  - Favicon (inline SVG data URI — no binary asset, matches the existing
    sidebar mark, nothing to "compress").
  - Meta description (harmless, helps if the tab/bookmark is shared
    internally).
  - Form validation: the live-capture `interface` field accepted anything
    client-side and would only fail after a round-trip with a raw 422.
    Added the same regex the backend already enforces, with an inline hint
    and a disabled button state instead of a trip to the server to find out.
  - Page load speed: route-level code-splitting via `React.lazy` +
    `Suspense`. Verified concretely, not just claimed — before: one 660KB
    chunk; after: Analysis/Control/Alerts/Flows/NotFound each split into
    their own chunk (Analysis alone, the heaviest non-landing page at
    29.5KB, is no longer in the initial load). The landing-page bundle is
    still ~612KB because Dashboard's own charts need `recharts` immediately
    — further reduction would mean removing charts from the dashboard,
    which wasn't asked for.
  - HTTPS enforcement: this was already in SECURITY.md as prose; added
    `docs/enforce-https.md` with working Caddy and nginx+certbot configs,
    and *verified* (by reading the code, not assuming) that the frontend's
    existing `wss://`/`https://` detection in `lib/api.js` already handles
    being served through a real reverse-proxy domain with no code change.
  - Broken links / image alt text / image compression: audited and
    confirmed N/A rather than silently skipped — all 5 sidebar nav targets
    match defined routes exactly, and there isn't a single `<img>` tag
    anywhere in the frontend (everything is inline SVG/emoji/CSS), so
    there's no alt text to write and nothing to compress.
  - "Remove frontend secrets" was already satisfied by the API-key
    architecture from the hardening pass — reconfirmed, not re-done.

## Minor fix while writing project docs
Found a stale path reference while cross-referencing `architecture.md`
against the actual frontend: the Sidebar footer linked to `docs/SECURITY.md`,
but `SECURITY.md` has always lived at the repo root — `docs/` only contains
`enforce-https.md`. Fixed the string; noting it here since it's exactly the
kind of small drift that compounds if undocumented.

## Testing performed

Not just written — actually run:
- Pydantic validation: unit-tested every rejection case (bad interface,
  non-loopback target, unknown threshold key, out-of-range value).
- Auth: `TestClient` runs confirming 401 without a key, 200 with the right
  one, and the same for the WS ticket flow (mint → consume → reject-on-reuse
  → reject-garbage → unauthenticated-rejected).
- Rate limiter: direct unit test of the allow/block sequence.
- Threshold routing fix: confirmed `alert_threshold` and `contamination`
  actually change on the live objects, and that no stray key gets left in
  `stat_detector.t`.
- Dependency upgrades: full backend test suite + detection pipeline
  (statistical + ML detectors + alert manager) re-run against the upgraded
  package set; frontend rebuilt and dev server boot-tested after each
  dependency bump.
- C engine: full compile + link against the real nDPI static library with
  `-Wall -Wextra`, zero warnings.
