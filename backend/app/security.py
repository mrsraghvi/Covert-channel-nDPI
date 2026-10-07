"""
security.py — auth, rate limiting, and audit logging for the CovertScope API.

Design goals (see SECURITY.md for the full write-up):
  - Fail closed: every route that can change state or read captured traffic
    data requires a valid API key, by default. Only /api/health is public.
  - No secrets in source: the key is read from the environment, never
    hardcoded, and compared with a constant-time check.
  - Sensible dev ergonomics: if no key is configured, we generate a random
    ephemeral one at startup and print it once, loudly, instead of silently
    running wide open. This is meant for local/dev use only — real
    deployments must set COVERTSCOPE_API_KEY explicitly (docker-compose
    enforces this, see docker-compose.yml).
"""
from __future__ import annotations

import hmac
import logging
import os
import secrets
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request, WebSocket, status

log = logging.getLogger("covertscope.security")

# --------------------------------------------------------------------- #
# API key
# --------------------------------------------------------------------- #
_ENV_KEY = "COVERTSCOPE_API_KEY"


def _load_or_generate_api_key() -> tuple[str, bool]:
    key = os.getenv(_ENV_KEY)
    if key:
        if len(key) < 16:
            log.warning(
                "%s is set but shorter than 16 chars — use a longer random "
                "value, e.g. `openssl rand -hex 32`.", _ENV_KEY,
            )
        return key, False

    ephemeral = secrets.token_hex(32)
    log.warning(
        "\n"
        "==================================================================\n"
        " %s is not set — generating a temporary, random API key for this\n"
        " run only. It will change on every restart and is NOT suitable for\n"
        " anything beyond local/dev use.\n"
        "\n"
        "   Ephemeral API key: %s\n"
        "\n"
        " Set %s in your environment (or backend/.env) to pin a stable key.\n"
        "==================================================================",
        _ENV_KEY, ephemeral, _ENV_KEY,
    )
    return ephemeral, True


API_KEY, API_KEY_IS_EPHEMERAL = _load_or_generate_api_key()

# Routes that never require an API key (liveness/readiness probes).
PUBLIC_PATHS = {"/api/health"}


def _valid_key(candidate: str | None) -> bool:
    if not candidate:
        return False
    return hmac.compare_digest(candidate, API_KEY)


async def require_api_key(request: Request, x_api_key: str | None = Header(default=None)):
    """FastAPI dependency: raise 401 unless a valid X-API-Key header is present."""
    if not _valid_key(x_api_key):
        client = request.client.host if request.client else "unknown"
        log.warning("rejected request: missing/invalid API key from %s -> %s", client, request.url.path)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing or invalid API key")
    return True


async def require_api_key_ws(websocket: WebSocket) -> bool:
    """WS auth. Prefers a short-lived ticket (see mint_ws_ticket /
    consume_ws_ticket below) over the raw API key: browsers can't set
    custom headers on the WS handshake, and a long-lived secret sitting in
    a URL query string ends up in browser history, proxy access logs, and
    Referer headers — exactly what a ticket avoids. The raw key in ?key= is
    still accepted for scripts/CLI use where that trade-off is acceptable."""
    ticket = websocket.query_params.get("ticket")
    if ticket and consume_ws_ticket(ticket):
        return True

    candidate = websocket.headers.get("x-api-key") or websocket.query_params.get("key")
    if _valid_key(candidate):
        return True

    client = websocket.client.host if websocket.client else "unknown"
    log.warning("rejected websocket: missing/invalid API key/ticket from %s", client)
    return False


# --------------------------------------------------------------------- #
# WebSocket tickets: POST /api/ws-ticket (behind the normal API-key
# dependency) exchanges the long-lived key for a random, single-use,
# short-lived ticket the frontend then puts in the WS URL instead of the
# key itself. Keeps the durable secret out of anything that gets logged.
# --------------------------------------------------------------------- #
_WS_TICKET_TTL_S = 30.0
_ws_tickets: dict[str, float] = {}


def mint_ws_ticket() -> str:
    ticket = secrets.token_urlsafe(32)
    _ws_tickets[ticket] = time.time() + _WS_TICKET_TTL_S
    # Opportunistic cleanup so this dict can't grow unbounded if tickets are
    # minted but never consumed (e.g. the client never opens the socket).
    now = time.time()
    for t, exp in list(_ws_tickets.items()):
        if exp < now:
            _ws_tickets.pop(t, None)
    return ticket


def consume_ws_ticket(ticket: str) -> bool:
    """Single-use: a valid ticket is removed the moment it's checked,
    whether or not the caller goes on to use it, so it can't be replayed."""
    exp = _ws_tickets.pop(ticket, None)
    return exp is not None and exp >= time.time()


def audit(action: str, request: Request, **fields):
    """Lightweight audit trail for sensitive actions (capture/generator
    control, threshold changes, alert ack). Never logs the API key itself."""
    client = request.client.host if request.client else "unknown"
    extra = " ".join(f"{k}={v!r}" for k, v in fields.items())
    log.info("AUDIT action=%s client=%s %s", action, client, extra)


# --------------------------------------------------------------------- #
# Minimal in-memory rate limiter (sliding window per client IP + bucket).
# Good enough for a single-process lab deployment; swap for a shared store
# (e.g. Redis) if you run multiple backend workers/replicas.
# --------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self):
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, bucket: str, client_ip: str, limit: int, window_s: float = 60.0) -> bool:
        key = (bucket, client_ip)
        now = time.time()
        q = self._hits[key]
        while q and now - q[0] > window_s:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


rate_limiter = RateLimiter()


def enforce_rate_limit(bucket: str, limit: int, window_s: float = 60.0):
    """FastAPI dependency factory: `Depends(enforce_rate_limit("generator", 5, 60))`."""

    async def _dep(request: Request):
        client_ip = request.client.host if request.client else "unknown"
        if not rate_limiter.check(bucket, client_ip, limit, window_s):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"rate limit exceeded for '{bucket}' ({limit}/{int(window_s)}s)",
            )

    return _dep
