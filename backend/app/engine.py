from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("covertscope.engine")

sys.path.append(str(Path(__file__).resolve().parents[2] / "detection"))
from alert_manager import AlertManager  # noqa: E402
from feature_extractor import extract_features  # noqa: E402
from ml_detector import MLDetector  # noqa: E402
from statistical_detector import StatisticalDetector  # noqa: E402

from .database import Alert, AsyncSessionLocal, Flow


_MAX_TEXT_FIELD = 2048   # cap for Text columns (dns_query, http_user_agent, http_url) — the
                          # ingest line itself is already capped at MAX_LINE_BYTES, this just
                          # keeps any single field from dominating a row's storage
_MAX_SHORT_FIELD = 255    # cap for VARCHAR-backed columns (http_host mirrors the DB's own
                          # limit; the rest just guard against a misbehaving/compromised
                          # C engine sending oversized garbage)


def _safe_str(value: Any, max_len: int) -> str | None:
    if value is None:
        return None
    s = str(value)
    return s[:max_len]


def _safe_int(value: Any, default: int = 0, lo: int = 0, hi: int = 2_000_000_000) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _sanitize_flow(raw_flow: dict[str, Any]) -> dict[str, Any]:
    """The flow-ingest socket accepts JSON from an authenticated peer, but
    'authenticated' isn't the same as 'trusted to be well-formed' — a buggy
    or compromised C engine could still send oversized strings or bogus
    numeric fields. Coerce everything to sane types/bounds before it ever
    reaches an f-string, a DB column, or an int addition, so one bad record
    can't blow up the ingest task (which would otherwise silently drop
    every flow behind it in that connection) or bloat storage."""
    return {
        "flow_id": _safe_int(raw_flow.get("flow_id"), default=None) if raw_flow.get("flow_id") is not None else None,
        "src": _safe_str(raw_flow.get("src"), 128),
        "dst": _safe_str(raw_flow.get("dst"), 128),
        "l4_proto": _safe_str(raw_flow.get("l4_proto", "TCP"), 8),
        "protocol": _safe_str(raw_flow.get("protocol", "Unknown"), 64),
        "ndpi_proto_id": _safe_int(raw_flow.get("ndpi_proto_id"), default=0, hi=100_000),
        "packets": _safe_int(raw_flow.get("packets"), default=0, hi=100_000_000),
        "bytes": _safe_int(raw_flow.get("bytes"), default=0, hi=1_000_000_000_000),
        "duration_ms": _safe_int(raw_flow.get("duration_ms"), default=0, hi=86_400_000),  # 24h cap
        "dns_query": _safe_str(raw_flow.get("dns_query"), _MAX_TEXT_FIELD),
        "http_host": _safe_str(raw_flow.get("http_host"), _MAX_SHORT_FIELD),
        "http_user_agent": _safe_str(raw_flow.get("http_user_agent"), _MAX_TEXT_FIELD),
        "http_url": _safe_str(raw_flow.get("http_url"), _MAX_TEXT_FIELD),
        "covert_flags": _safe_int(raw_flow.get("covert_flags"), default=0, hi=0xFFFFFFFF),
    }


class ConnectionManager:
    """Tracks active websocket clients and broadcasts JSON messages."""

    def __init__(self):
        self.active: set = set()

    async def connect(self, ws):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws):
        self.active.discard(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


class IngestEngine:
    """Central place a flow record lands, regardless of whether it came
    from the C nDPI engine's TCP socket or the built-in traffic simulator.
    Runs it through both detectors, persists to Postgres, and pushes a
    live update to any connected dashboard clients."""

    def __init__(self, ws_manager: ConnectionManager):
        self.ws_manager = ws_manager
        self.stat_detector = StatisticalDetector()
        self.ml_detector = MLDetector()
        self.alert_manager = AlertManager()
        self.capture_active = False
        self.capture_mode = "stopped"
        self._flow_counter = 0
        self.totals = {"packets": 0, "bytes": 0, "flows": 0, "alerts": 0}
        self._rate_window: list[tuple[float, int, int]] = []  # (ts, pkts, bytes)
        # ip -> reason, kept in memory for a cheap per-flow lookup on the hot
        # ingest path. The database row is the source of truth; this is a
        # cache of it populated at startup and kept in sync by
        # block_ip()/unblock_ip() (called from the API layer, see main.py).
        self.blocked_ips: dict[str, str | None] = {}

    def is_blocked(self, ip: str | None) -> bool:
        return bool(ip) and ip in self.blocked_ips

    def block_ip(self, ip: str, reason: str | None = None):
        self.blocked_ips[ip] = reason

    def unblock_ip(self, ip: str):
        self.blocked_ips.pop(ip, None)

    async def ingest(self, raw_flow: dict[str, Any]):
        self._flow_counter += 1
        flow_id = raw_flow.get("flow_id", self._flow_counter)

        features = extract_features(raw_flow)
        stat_result = self.stat_detector.evaluate(features)
        ml_score = self.ml_detector.score(features)
        alert = self.alert_manager.evaluate(
            flow_id=flow_id,
            covert_type=stat_result.covert_type,
            stat_score=stat_result.score,
            ml_score=ml_score,
            reasons=stat_result.reasons,
        )

        final_score = self.alert_manager.combine(stat_result.score, ml_score)
        is_covert = final_score >= self.alert_manager.alert_threshold

        src_ip, src_port = _split_endpoint(raw_flow.get("src"))
        dst_ip, dst_port = _split_endpoint(raw_flow.get("dst"))
        src_ip = src_ip or "0.0.0.0"
        dst_ip = dst_ip or "0.0.0.0"
        is_blocked = self.is_blocked(src_ip) or self.is_blocked(dst_ip)

        now = time.time()
        self.totals["packets"] += raw_flow.get("packets", 0)
        self.totals["bytes"] += raw_flow.get("bytes", 0)
        self.totals["flows"] += 1
        self._rate_window.append((now, raw_flow.get("packets", 0), raw_flow.get("bytes", 0)))
        self._rate_window = [r for r in self._rate_window if now - r[0] < 10]

        async with AsyncSessionLocal() as session:
            db_flow = Flow(
                flow_uid=flow_id,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                l4_proto=raw_flow.get("l4_proto", "TCP"),
                ndpi_protocol=raw_flow.get("protocol", "Unknown"),
                ndpi_proto_id=raw_flow.get("ndpi_proto_id", 0),
                packets=raw_flow.get("packets", 0),
                bytes=raw_flow.get("bytes", 0),
                duration_ms=raw_flow.get("duration_ms", 0),
                iat_mean=features.iat_mean,
                iat_variance=features.iat_variance,
                iat_cv=features.iat_cv,
                iat_autocorr1=features.iat_autocorr1,
                payload_entropy=features.payload_entropy,
                avg_pkt_len=features.avg_pkt_len,
                dns_query=raw_flow.get("dns_query"),
                dns_entropy=features.dns_entropy,
                dns_qlen=features.dns_qlen,
                dns_qps=features.dns_qps,
                http_host=raw_flow.get("http_host"),
                http_user_agent=raw_flow.get("http_user_agent"),
                http_url=raw_flow.get("http_url"),
                http_ua_entropy=features.http_ua_entropy,
                icmp_payload_len=features.icmp_payload_len,
                icmp_payload_entropy=features.icmp_payload_entropy,
                covert_flags=raw_flow.get("covert_flags", 0),
                anomaly_score=final_score,
                is_covert=is_covert,
                blocked=is_blocked,
            )
            session.add(db_flow)
            await session.flush()

            db_alert = None
            if alert:
                self.totals["alerts"] += 1
                db_alert = Alert(
                    flow_id=db_flow.id,
                    covert_type=alert.covert_type,
                    stat_score=alert.stat_score,
                    ml_score=alert.ml_score,
                    final_score=alert.final_score,
                    confidence=alert.confidence,
                    reason=alert.reason,
                    recommendation=alert.recommendation,
                )
                session.add(db_alert)

            await session.commit()
            await session.refresh(db_flow)
            if db_alert:
                await session.refresh(db_alert)

        payload = {
            "type": "flow",
            "flow": {
                "id": db_flow.id,
                "src": raw_flow.get("src"),
                "dst": raw_flow.get("dst"),
                "protocol": db_flow.ndpi_protocol,
                "packets": db_flow.packets,
                "bytes": db_flow.bytes,
                "duration_ms": db_flow.duration_ms,
                "iat_cv": features.iat_cv,
                "payload_entropy": features.payload_entropy,
                "anomaly_score": final_score,
                "is_covert": is_covert,
                "blocked": is_blocked,
                "ts": now,
            },
        }
        await self.ws_manager.broadcast(payload)

        if alert:
            await self.ws_manager.broadcast({
                "type": "alert",
                "alert": {
                    "id": db_alert.id if db_alert else None,
                    "flow_id": db_flow.id,
                    "covert_type": alert.covert_type,
                    "final_score": alert.final_score,
                    "confidence": alert.confidence,
                    "reason": alert.reason,
                    "recommendation": alert.recommendation,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ts": now,
                },
            })

        return db_flow, alert

    def current_rate(self) -> tuple[float, float]:
        if not self._rate_window:
            return 0.0, 0.0
        span = max(1.0, time.time() - self._rate_window[0][0])
        pkts = sum(r[1] for r in self._rate_window)
        byts = sum(r[2] for r in self._rate_window)
        return pkts / span, byts / span


def _split_endpoint(hostport: str | None) -> tuple[str | None, int | None]:
    if not hostport:
        return None, None
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0 or end + 1 >= len(hostport) or hostport[end + 1] != ":":
            return None, None
        address, port_text = hostport[1:end], hostport[end + 2:]
    elif ":" in hostport:
        address, _, port_text = hostport.rpartition(":")
    else:
        return hostport, None
    if not address:
        return None, None
    try:
        port = int(port_text)
    except ValueError:
        return address, None
    return address, port if 0 <= port <= 65535 else None


_INGEST_SECRET_ENV = "COVERTSCOPE_INGEST_SECRET"
MAX_LINE_BYTES = 65536          # a single flow record should never approach this
MAX_BUFFER_BYTES = 262144       # hard cap before we drop the connection (anti-DoS)
AUTH_TIMEOUT_S = 5.0


def _ingest_secret() -> str | None:
    """Shared secret the C nDPI engine must present before any flow records
    are accepted. Unset by default only for zero-config local dev; set it
    (and pass the same value to covert_detector via COVERTSCOPE_INGEST_SECRET)
    for anything beyond a single trusted host."""
    return os.getenv(_INGEST_SECRET_ENV)


async def tcp_ingest_server(engine: IngestEngine, host: str | None = None, port: int = 9999):
    """Listens for newline-delimited JSON flow records from the C nDPI
    engine (covert_channel_detector) and feeds them into the pipeline.

    Wire protocol: if COVERTSCOPE_INGEST_SECRET is set, the first line the
    client sends must be exactly `AUTH <secret>`; anything else (or a
    timeout) closes the connection before any flow data is parsed. This
    stops an arbitrary process that can reach the port from injecting fake
    flows / poisoning the detector or the database.
    """
    host = host or os.getenv("COVERTSCOPE_INGEST_HOST", "0.0.0.0")
    secret = _ingest_secret()
    if not secret:
        log.warning(
            "%s is not set — the flow-ingest socket on :%d will accept "
            "records from any host that can reach it. Set %s (and pass the "
            "same value to covert_detector) for anything beyond an isolated "
            "lab host.",
            _INGEST_SECRET_ENV, port, _INGEST_SECRET_ENV,
        )

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        buf = b""

        if secret:
            try:
                first_line = await asyncio.wait_for(reader.readline(), timeout=AUTH_TIMEOUT_S)
            except asyncio.TimeoutError:
                log.warning("ingest auth timeout from %s", peer)
                writer.close()
                return
            presented = first_line.strip()
            expected = f"AUTH {secret}".encode()
            if not presented or not hmac.compare_digest(presented, expected):
                log.warning("ingest auth failed from %s", peer)
                writer.close()
                return
            log.info("ingest client authenticated: %s", peer)

        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_BUFFER_BYTES:
                    log.warning("ingest buffer exceeded from %s, dropping connection", peer)
                    break
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    if len(line) > MAX_LINE_BYTES:
                        continue
                    try:
                        record = json.loads(line)
                        if isinstance(record, dict) and record.get("type") == "flow":
                            await engine.ingest(record)
                    except json.JSONDecodeError:
                        continue
        finally:
            writer.close()

    server = await asyncio.start_server(handle, host, port)
    async with server:
        await server.serve_forever()
