# Security notes

CovertScope is a research/lab tool for detecting covert network channels.
It is **not** hardened for exposure on an untrusted network by default —
this document describes what's protected, what isn't, and what to change
before running it anywhere beyond an isolated lab host.

## Trust model

Assume:
- The operator running `docker-compose up` (or the bare services) is
  trusted and controls the `.env` file / environment.
- Anyone who can reach the API port, the WebSocket, or the ingest socket
  is **not** trusted by default and must present a key.
- The dashboard's static JS bundle is public — it is served to any browser
  that loads the page, so **nothing secret is baked into it**. The
  operator pastes the API key into the dashboard at runtime; it lives only
  in that tab's `sessionStorage`.

## What's protected

| Surface | Control |
|---|---|
| REST API (`/api/*`, except `/api/health`) | `X-API-Key` header, constant-time compared against `COVERTSCOPE_API_KEY` |
| WebSocket (`/ws`) | Same key, passed as `?key=` (browsers can't set custom headers on the WS handshake) |
| Flow-ingest socket (`:9999`, fed by the C nDPI engine) | `AUTH <secret>` handshake line using `COVERTSCOPE_INGEST_SECRET`, checked before any JSON is parsed; oversized lines/buffers are dropped |
| `/api/capture/start`, `/api/generator/start` | Rate-limited (10/min and 5/min per client IP) on top of the API key, since these start background processes |
| Generator target | Validated as loopback by Pydantic *and* independently by `generator.py` itself — two independent checks, not one relying on the other |
| Threshold updates | Key whitelist + numeric bounds, so the endpoint can't be used to write arbitrary rows or wildly out-of-range values |
| Capture `interface` / `bpf_filter` | Regex/length constrained — these are only ever displayed back in a note string, but constrained anyway since they're attacker-controlled input |
| CORS | Explicit origin allowlist (`CORS_ORIGINS`), `allow_credentials=False` — no more `*` + credentials |
| Secrets | Sourced from `.env` (gitignored), `docker-compose up` fails fast with a clear message if `POSTGRES_PASSWORD` / `COVERTSCOPE_API_KEY` / `COVERTSCOPE_INGEST_SECRET` aren't set |
| Containers | Backend runs as a non-root user, `read_only` root filesystem, `no-new-privileges`; Postgres is not published to the host by default |

## What's intentionally out of scope / residual risk

- **Single shared API key, not per-user auth.** This is a lab tool for one
  operator (or a small trusted team sharing one key), not a multi-tenant
  system. If you need per-user accounts, audit trails tied to identity, or
  RBAC, put this behind an actual auth proxy/IdP.
- **In-memory rate limiter.** Fine for a single backend process; if you
  scale to multiple replicas, the limits are per-process, not global —
  swap in a shared store (Redis, etc.) if that matters to you.
- **No TLS termination here.** `docker-compose.yml` serves plain HTTP/WS.
  Put a real reverse proxy (nginx, Caddy, Traefik) with a TLS cert in
  front of this for anything beyond `localhost`, and set `CORS_ORIGINS`
  accordingly (the frontend's WS/API URL logic already adapts automatically
  — see `docs/enforce-https.md` for ready-to-use configs and what does/
  doesn't need to change).
- **`nginx:alpine` master process still starts as root** to bind the
  listening socket (standard nginx behavior); workers run as the `nginx`
  user. Switch to an unprivileged nginx image if you need to remove this.
- **Ephemeral dev API key.** If you run the backend directly (not via
  compose) without setting `COVERTSCOPE_API_KEY`, it generates a random
  key each start and logs it once. Convenient for local dev, actively bad
  for anything you leave running unattended — set the env var.

## Before running this anywhere beyond your own machine

1. `cp .env.example .env` and fill in real, random values
   (`openssl rand -hex 32` for each secret).
2. Put a TLS-terminating reverse proxy in front of the frontend and
   backend ports.
3. Set `CORS_ORIGINS` to your real dashboard origin(s) only.
4. Keep the generator restricted to loopback (it already refuses anything
   else, twice — don't "fix" that).
5. Only expose the flow-ingest port (`:9999`) to hosts that actually run
   the nDPI C engine, and set `COVERTSCOPE_INGEST_SECRET`.
6. Get authorization before running packet capture or generating test
   traffic on any network, including your own — see the main README.
