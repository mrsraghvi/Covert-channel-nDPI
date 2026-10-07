# Coding rules — CovertScope

These are working rules for anyone (human or AI) changing this codebase,
derived from how the project is actually built, not generic style
preferences. Where a rule exists because of a real bug or incident caught
during development, that's noted — these aren't hypothetical.

## 1. Security rules (non-negotiable)

- **Every new `/api/*` route requires `auth_dep` in `dependencies=[...]`**
  unless it's a genuine liveness probe like `/api/health`. Don't rely on
  remembering to add it per-route if you can apply it at a router level
  instead — a route that's added without it is a route that's open to
  anyone who can reach the port.
- **Never trust a generator/capture `target`, `interface`, or threshold
  `key` on the strength of one validation layer.** The generator target is
  validated as loopback *twice*, independently (Pydantic in `schemas.py`,
  and `generator.py`'s own check) — this is deliberate defense-in-depth,
  not duplication to clean up. If you add a new attacker-reachable
  parameter that gates a privileged action, ask whether it needs the same
  two-layer treatment.
- **Any new threshold key must be added in three places that must agree**:
  `database/schema.sql`'s seed rows, `schemas.py::KNOWN_THRESHOLD_KEYS`,
  and `main.py::put_threshold`'s routing (which component actually reads
  it: `stat_detector.t`, `alert_manager.alert_threshold`, or
  `ml_detector.contamination`). A key present in the DB/whitelist but not
  routed to a real attribute is a silent no-op — this exact bug existed for
  `alert_score`/`ml_contamination` before it was caught and fixed. Write a
  test that actually checks the live attribute changed, not just that the
  endpoint returned 200.
- **Never shell out with `shell=True`, and never construct a command
  string by concatenation.** `subprocess.Popen(cmd, ...)` always takes a
  list (see `main.py::generator_start`). If a request field is going to
  end up in a subprocess argument, validate its format at the schema layer
  first regardless of whether the list form is already injection-safe.
- **Don't add real inline enforcement (iptables/nftables, process kill,
  anything that mutates host/network state beyond the DB) to the main
  backend.** See `architecture.md` §Blocklist for why. If you need real
  enforcement, it's a new, separately-privileged service, not a new
  capability on this container.
- **The API key never gets embedded in anything served to a browser.**
  No baking it into a frontend build arg, no writing it into a static
  asset. It's entered at runtime and lives in `sessionStorage` only
  (`frontend/src/lib/api.js`). If a feature seems to need the key at build
  time, that's a sign the design is wrong, not that this rule should bend.
- **WebSocket auth prefers the ticket exchange over a raw key in the URL**
  (`POST /api/ws-ticket` → `?ticket=`). A URL-embedded secret ends up in
  browser history and proxy/access logs; a 30-second single-use ticket
  doesn't. Keep the raw-key-in-URL fallback for script/CLI use, but new
  frontend code should go through the ticket path.
- **Run `pip-audit` / `npm audit` before bumping or adding any dependency,
  and periodically regardless.** Dependencies pinned in this repo had 16
  and 5 known CVEs respectively before the last audit pass — version
  pinning isn't a substitute for checking it stayed clean.

## 2. Validation rules

- Every Pydantic model for a mutating endpoint gets explicit bounds:
  `Literal` enums instead of bare `str` wherever the valid set is known
  (`technique`, `mode`), `Field(max_length=...)` on every free-text field,
  numeric `Field(ge=..., le=...)` on every tunable. An unconstrained field
  on a write endpoint is a bug, not an oversight to fix later.
- IP-shaped input gets parsed with `ipaddress.ip_address()`, never regex.
  Reject, don't normalize-and-accept.
- Control characters are stripped/rejected from any free-text field that
  gets logged or displayed (`bpf_filter`, blocklist `reason`) — not for
  injection reasons (nothing executes them) but to stop log/display
  corruption and copy-paste surprises.
- When you add a whitelist (threshold keys, enum values), **derive it from
  the actual schema/seed data, not from what the current UI happens to
  expose.** A whitelist narrower than reality silently breaks legitimate
  future callers — this happened once already (see `rules.md` §1 above
  and `CODE_REVIEW.md`).

## 3. Testing discipline

- **A route returning 200 is not a passing test.** Test that the
  underlying state actually changed the way the route claims (the
  threshold-routing bug and the `active_only` filter bug in the blocklist
  work were both caught this way, not by status-code checks).
- When mocking the DB layer for a test (no live Postgres available), build
  the fake incrementally against what the real query actually does — don't
  assume a fake session that always returns `rowcount=1` or an empty list
  is good enough. Two real test-harness bugs were caught this way (a fake
  `UPDATE` not modeling "no row matched", a fake `SELECT` not modeling
  "select all" vs. "select by key") — both were in the test code, not the
  app, but both would have hidden a real app bug if left unfixed.
- Prefer testing against a real Postgres instance when one is available.
  When it isn't (e.g. a broken package mirror with no way to route around
  it), say so explicitly in the commit/PR/summary rather than silently
  presenting fake-session tests as equivalent coverage.
- Before upgrading a dependency, re-run the full test suite against the
  new version and actually look at the output — don't assume semver.
- After any frontend change, run the actual build (`npm run build`), not
  just a lint/typecheck. Vite/esbuild catch real import and JSX errors the
  dev server sometimes doesn't surface.

## 4. Frontend conventions

- **No `dangerouslySetInnerHTML`, anywhere, ever**, in this codebase.
  Flow fields like `dns_query` and `http_host` are attacker-influenced —
  they come from real (or generator-simulated) network traffic. Plain JSX
  text nodes only; React's escaping is load-bearing here.
- **No `localStorage` for anything sensitive.** The API key lives in
  `sessionStorage`, which clears on tab close. A feature asking for
  persistence across browser restarts is asking for the wrong storage —
  push back on the requirement, don't switch to `localStorage`.
- State that multiple pages need (live flows/alerts, the blocklist map,
  connection status) lives in `useLiveData.js`, the single hook `App.jsx`
  calls and threads down as props. Don't fetch the same data independently
  in two pages — add it to the shared hook.
- Every page must degrade sanely into demo mode (no backend reachable).
  Follow the existing pattern: try the real `api.*` call, catch and
  fall back to local-only state, don't throw.
- New dependencies: check `npm audit` immediately after adding, and prefer
  the smallest library that does the job — `recharts` is already the
  single largest dependency in the bundle; don't add a second charting
  library.
- Route-level code splitting (`React.lazy`) is the existing pattern for
  anything that isn't the landing page (`Dashboard`). New pages should
  follow it rather than being eagerly imported in `App.jsx`.

## 5. Documentation discipline

- If you make a scope decision that could be read either way (e.g., does
  "block" mean drop packets or just flag/export?), **say so explicitly in
  the code comment and in whatever summary goes back to whoever asked** —
  don't silently pick the narrower, safer interpretation and let them find
  out later. See how the blocklist's docstring in `database.py` and
  `architecture.md` §Blocklist both state this up front.
- When you find a pre-existing bug while working on something else (the
  threshold-routing no-op, the unused `capture_sessions` table), document
  it where it'll be found — `CODE_REVIEW.md` for security-relevant history,
  `tasks.md`/`architecture.md` for anything structural — rather than
  quietly fixing or quietly ignoring it.
- `SECURITY.md` and `CODE_REVIEW.md` are living documents. A change that
  affects the threat model or adds/removes a control updates them in the
  same change, not as a follow-up.
