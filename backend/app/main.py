from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import (Depends, FastAPI, File, HTTPException, Query, Request,
                      UploadFile, WebSocket, WebSocketDisconnect)
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, update

from .database import (
    Alert, AsyncSessionLocal, BlockedIP, Flow, Threshold, engine as db_engine,
)
from .engine import ConnectionManager, IngestEngine, tcp_ingest_server
from .migrations import upgrade_database
from .pcap_replay import PcapReplayError, parse_pcap
from .schemas import (AlertOut, BlockCreate, BlockOut, CaptureStartRequest,
                       FlowOut, GeneratorStartRequest, StatsOut,
                       ThresholdUpdate)
from .security import (audit, enforce_rate_limit, mint_ws_ticket,
                        require_api_key, require_api_key_ws)
from .simulator import run_simulator

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("covertscope")

ws_manager = ConnectionManager()
engine = IngestEngine(ws_manager)

_sim_task: asyncio.Task | None = None
_sim_stop_event: asyncio.Event | None = None
_tcp_task: asyncio.Task | None = None
_generator_proc: subprocess.Popen | None = None

# Resolve generator.py relative to this file, not the process cwd — running
# uvicorn from a different working directory used to silently break (or
# invoke the wrong script from) the relative "../generator/generator.py" path.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_GENERATOR_SCRIPT = _REPO_ROOT / "generator" / "generator.py"
_MAX_PCAP_BYTES = 25 * 1024 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    await upgrade_database(db_engine)
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(select(BlockedIP).where(BlockedIP.active == True))).scalars().all()  # noqa: E712
        for r in rows:
            engine.block_ip(r.ip, r.reason)
    log.info("loaded %d active blocklist entries", len(engine.blocked_ips))
    global _tcp_task
    _tcp_task = asyncio.create_task(tcp_ingest_server(engine))
    log.info("CovertScope backend started. nDPI ingest socket listening on :9999")
    yield
    if _tcp_task:
        _tcp_task.cancel()


app = FastAPI(title="CovertScope API", version="1.0.0", lifespan=lifespan)

# ------------------------------------------------------------------ CORS --
# Wildcard origins + credentials is both invalid per the fetch spec and a
# bad default for an API that controls packet capture / traffic generation.
# Configure real origins via CORS_ORIGINS (comma-separated) in production;
# the defaults below only cover the local Vite dev server and the dockerized
# frontend's host-mapped port.
_default_origins = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173"
_cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", _default_origins).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = response.headers.get("Cache-Control", "no-store")
    return response


# Small cap for normal API requests. PCAP replay has its own explicit,
# larger cap below so large uploads cannot expand the accepted size of other
# routes.
_MAX_BODY_BYTES = 64 * 1024


@app.middleware("http")
async def limit_body_size(request, call_next):
    content_length = request.headers.get("content-length")
    if request.url.path == "/api/capture/replay" and (
        not content_length or not content_length.isdigit()
    ):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=411,
            content={"detail": "PCAP replay requires a Content-Length header"},
        )
    max_body = _MAX_PCAP_BYTES + 1024 * 1024 if request.url.path == "/api/capture/replay" else _MAX_BODY_BYTES
    if content_length and content_length.isdigit() and int(content_length) > max_body:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=413, content={"detail": "request body too large"})
    return await call_next(request)


# All routes require a valid API key except /api/health (liveness probe).
# Applied as a dependency on the router rather than per-route so a new
# endpoint added later is protected by default instead of by remembering to
# add it.
auth_dep = Depends(require_api_key)


# ----------------------------------------------------------------- health --
@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "capture_active": engine.capture_active,
        "capture_mode": engine.capture_mode,
        "flows_ingested": engine.totals["flows"],
        "alerts_raised": engine.totals["alerts"],
        "ts": time.time(),
    }


# ------------------------------------------------------------------ stats --
@app.get("/api/stats", response_model=StatsOut, dependencies=[auth_dep])
async def get_stats():
    async with AsyncSessionLocal() as session:
        total_flows = (await session.execute(select(func.count(Flow.id)))).scalar() or 0
        total_alerts = (await session.execute(select(func.count(Alert.id)))).scalar() or 0
        covert_flows = (
            await session.execute(select(func.count(Flow.id)).where(Flow.is_covert == True))  # noqa: E712
        ).scalar() or 0

        proto_rows = (
            await session.execute(
                select(Flow.ndpi_protocol, func.count(Flow.id)).group_by(Flow.ndpi_protocol)
            )
        ).all()
        protocol_distribution = {p or "Unknown": c for p, c in proto_rows}

        conf_rows = (
            await session.execute(select(Alert.confidence, func.count(Alert.id)).group_by(Alert.confidence))
        ).all()
        confidence_distribution = {c: n for c, n in conf_rows}

        type_rows = (
            await session.execute(select(Alert.covert_type, func.count(Alert.id)).group_by(Alert.covert_type))
        ).all()
        covert_type_distribution = {t: n for t, n in type_rows}

        avg_entropy = (await session.execute(select(func.avg(Flow.payload_entropy)))).scalar() or 0.0

    pkt_rate, byte_rate = engine.current_rate()

    return StatsOut(
        total_flows=total_flows,
        total_alerts=total_alerts,
        covert_flows=covert_flows,
        active_capture=engine.capture_active,
        protocol_distribution=protocol_distribution,
        confidence_distribution=confidence_distribution,
        covert_type_distribution=covert_type_distribution,
        avg_entropy=round(float(avg_entropy), 3),
        packets_per_sec=round(pkt_rate, 2),
        bytes_per_sec=round(byte_rate, 2),
    )


# ------------------------------------------------------------------ flows --
@app.get("/api/flows", response_model=list[FlowOut], dependencies=[auth_dep])
async def get_flows(
    protocol: str | None = None,
    covert_only: bool = False,
    limit: int = Query(100, le=1000),
):
    async with AsyncSessionLocal() as session:
        stmt = select(Flow).order_by(Flow.created_at.desc()).limit(limit)
        if protocol:
            stmt = stmt.where(Flow.ndpi_protocol == protocol)
        if covert_only:
            stmt = stmt.where(Flow.is_covert == True)  # noqa: E712
        rows = (await session.execute(stmt)).scalars().all()
        return [
            FlowOut(
                id=r.id, flow_uid=r.flow_uid, src_ip=str(r.src_ip), src_port=r.src_port,
                dst_ip=str(r.dst_ip), dst_port=r.dst_port, l4_proto=r.l4_proto,
                ndpi_protocol=r.ndpi_protocol, packets=r.packets, bytes=r.bytes,
                duration_ms=r.duration_ms, iat_mean=r.iat_mean, iat_cv=r.iat_cv,
                payload_entropy=r.payload_entropy, dns_query=r.dns_query,
                dns_entropy=r.dns_entropy, http_host=r.http_host,
                covert_flags=r.covert_flags, anomaly_score=r.anomaly_score,
                is_covert=r.is_covert, blocked=r.blocked, created_at=r.created_at,
            )
            for r in rows
        ]


# ----------------------------------------------------------------- alerts --
@app.get("/api/alerts", response_model=list[AlertOut], dependencies=[auth_dep])
async def get_alerts(
    min_confidence: str | None = None,
    covert_type: str | None = None,
    limit: int = Query(100, le=1000),
):
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    async with AsyncSessionLocal() as session:
        # Joined so the response carries src_ip/dst_ip directly — lets the
        # frontend offer a "block this source" action from the alert row
        # without a second round-trip to look the flow up.
        stmt = (
            select(Alert, Flow.src_ip, Flow.dst_ip)
            .join(Flow, Flow.id == Alert.flow_id, isouter=True)
            .order_by(Alert.created_at.desc())
            .limit(limit)
        )
        if covert_type:
            stmt = stmt.where(Alert.covert_type == covert_type)
        rows = (await session.execute(stmt)).all()
        out = [
            AlertOut(
                id=a.id, flow_id=a.flow_id, covert_type=a.covert_type,
                stat_score=a.stat_score, ml_score=a.ml_score, final_score=a.final_score,
                confidence=a.confidence, reason=a.reason, recommendation=a.recommendation,
                acknowledged=a.acknowledged, created_at=a.created_at,
                src_ip=str(src_ip) if src_ip is not None else None,
                dst_ip=str(dst_ip) if dst_ip is not None else None,
            )
            for a, src_ip, dst_ip in rows
        ]
        if min_confidence:
            floor = order.get(min_confidence.upper(), 0)
            out = [r for r in out if order.get(r.confidence, 0) >= floor]
        return out


@app.post("/api/alerts/{alert_id}/ack", dependencies=[auth_dep])
async def ack_alert(alert_id: int, request: Request):
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            update(Alert).where(Alert.id == alert_id).values(acknowledged=True)
        )
        await session.commit()
        if result.rowcount == 0:
            raise HTTPException(404, "alert not found")
    audit("alert_ack", request, alert_id=alert_id)
    return {"ok": True}


# --------------------------------------------------------------- blocklist --
# CovertScope is a passive monitor, not an inline enforcement point — see
# BlockedIP's docstring in database.py. These routes raise/clear a soft,
# advisory block: it's persisted, it flags any future matching flow, and
# it's exposed here for a real firewall/edge device to poll and enforce.
@app.get("/api/blocklist", response_model=list[BlockOut], dependencies=[auth_dep])
async def list_blocklist(active_only: bool = False, limit: int = Query(200, le=1000)):
    async with AsyncSessionLocal() as session:
        stmt = select(BlockedIP).order_by(BlockedIP.created_at.desc()).limit(limit)
        if active_only:
            stmt = stmt.where(BlockedIP.active == True)  # noqa: E712
        rows = (await session.execute(stmt)).scalars().all()
        return rows


@app.post(
    "/api/blocklist",
    response_model=BlockOut,
    dependencies=[auth_dep, Depends(enforce_rate_limit("blocklist_write", limit=30, window_s=60))],
)
async def block_ip(req: BlockCreate, request: Request):
    async with AsyncSessionLocal() as session:
        existing = (await session.execute(select(BlockedIP).where(BlockedIP.ip == req.ip))).scalar_one_or_none()
        if existing:
            existing.active = True
            existing.reason = req.reason or existing.reason
            existing.alert_id = req.alert_id if req.alert_id is not None else existing.alert_id
            row = existing
        else:
            row = BlockedIP(ip=req.ip, reason=req.reason, alert_id=req.alert_id, active=True)
            session.add(row)
        await session.commit()
        await session.refresh(row)

    engine.block_ip(req.ip, req.reason)
    audit("block_ip", request, ip=req.ip, alert_id=req.alert_id)
    await ws_manager.broadcast({
        "type": "blocklist",
        "action": "block",
        "ip": req.ip,
        "reason": req.reason,
        "ts": time.time(),
    })
    return row


@app.delete(
    "/api/blocklist/{ip}",
    dependencies=[auth_dep, Depends(enforce_rate_limit("blocklist_write", limit=30, window_s=60))],
)
async def unblock_ip(ip: str, request: Request):
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            update(BlockedIP).where(BlockedIP.ip == ip).values(active=False)
        )
        await session.commit()
        if result.rowcount == 0:
            raise HTTPException(404, f"'{ip}' is not on the blocklist")

    engine.unblock_ip(ip)
    audit("unblock_ip", request, ip=ip)
    await ws_manager.broadcast({"type": "blocklist", "action": "unblock", "ip": ip, "ts": time.time()})
    return {"ok": True, "ip": ip}


# --------------------------------------------------------------- capture --
@app.post(
    "/api/capture/replay",
    dependencies=[auth_dep, Depends(enforce_rate_limit("capture_replay", limit=5, window_s=60))],
)
async def capture_replay(request: Request, file: UploadFile = File(...)):
    if engine.capture_active:
        raise HTTPException(409, "stop the active capture before replaying a file")

    contents = await file.read(_MAX_PCAP_BYTES + 1)
    if len(contents) > _MAX_PCAP_BYTES:
        await file.close()
        raise HTTPException(413, "PCAP files must be 25 MiB or smaller")

    try:
        records, skipped_packets = await asyncio.to_thread(parse_pcap, contents)
    except PcapReplayError as exc:
        raise HTTPException(422, str(exc)) from exc
    finally:
        await file.close()

    if engine.capture_active:
        raise HTTPException(409, "another capture started while the file was being checked")

    engine.capture_active = True
    engine.capture_mode = "pcap-replay"
    alerts_raised = 0
    try:
        first_flow_id = engine._flow_counter + 1
        for offset, record in enumerate(records):
            record["flow_id"] = first_flow_id + offset
            _, alert = await engine.ingest(record)
            if alert:
                alerts_raised += 1
    finally:
        engine.capture_active = False
        engine.capture_mode = "stopped"

    filename = Path(file.filename or "capture.pcap").name[:120]
    audit(
        "capture_replay",
        request,
        filename=filename,
        flows=len(records),
        skipped_packets=skipped_packets,
    )
    return {
        "ok": True,
        "filename": filename,
        "flows_replayed": len(records),
        "alerts_raised": alerts_raised,
        "skipped_packets": skipped_packets,
    }


@app.post(
    "/api/capture/start",
    dependencies=[auth_dep, Depends(enforce_rate_limit("capture_start", limit=10, window_s=60))],
)
async def capture_start(req: CaptureStartRequest, request: Request):
    global _sim_task, _sim_stop_event
    if engine.capture_active:
        raise HTTPException(409, "capture already active")

    engine.capture_active = True
    engine.capture_mode = req.mode
    audit("capture_start", request, mode=req.mode, interface=req.interface)

    if req.mode == "simulated":
        _sim_stop_event = asyncio.Event()
        _sim_task = asyncio.create_task(run_simulator(engine, _sim_stop_event))
        return {"ok": True, "mode": "simulated", "note": "synthetic flow generator running"}

    # live mode: the operator is expected to separately run
    #   sudo ./ndpi-engine/covert_detector <interface> ["bpf filter"]
    # which streams JSON flow records to this backend on TCP :9999.
    return {
        "ok": True,
        "mode": "live",
        "note": (
            f"Waiting for the nDPI C engine to connect on :9999. "
            f"Run: sudo ./ndpi-engine/covert_detector {req.interface} "
            f"{repr(req.bpf_filter) if req.bpf_filter else ''}"
        ),
    }


@app.post("/api/capture/stop", dependencies=[auth_dep])
async def capture_stop(request: Request):
    global _sim_task, _sim_stop_event
    if not engine.capture_active:
        raise HTTPException(409, "capture not active")
    engine.capture_active = False
    if _sim_stop_event:
        _sim_stop_event.set()
    if _sim_task:
        await asyncio.wait([_sim_task], timeout=2)
    engine.capture_mode = "stopped"
    audit("capture_stop", request)
    return {"ok": True}


# ------------------------------------------------------------- generator --
@app.post(
    "/api/generator/start",
    dependencies=[auth_dep, Depends(enforce_rate_limit("generator_start", limit=5, window_s=60))],
)
async def generator_start(req: GeneratorStartRequest, request: Request):
    """Launches the lab-only covert-traffic generator against a
    loopback/lab target for validating the detection engine. The target is
    validated as loopback both here (schemas.GeneratorStartRequest) and
    independently inside generator.py itself, which will refuse to send
    anything to a non-loopback address regardless of how it's invoked."""
    global _generator_proc
    if _generator_proc and _generator_proc.poll() is None:
        raise HTTPException(409, "generator already running")

    if not _GENERATOR_SCRIPT.is_file():
        raise HTTPException(500, f"generator.py not found at {_GENERATOR_SCRIPT}")

    cmd = [
        sys.executable, str(_GENERATOR_SCRIPT),
        "--target", req.target,
        "--technique", req.technique,
        "--message", req.message,
        "--duration", str(req.duration_s),
    ]
    audit("generator_start", request, technique=req.technique, target=req.target, duration_s=req.duration_s)
    try:
        # No shell=True anywhere in this call — args are passed as a list,
        # so there's no shell-metacharacter injection surface even though
        # every field above is already constrained by GeneratorStartRequest.
        _generator_proc = subprocess.Popen(cmd, cwd=str(_REPO_ROOT / "generator"))
    except FileNotFoundError:
        raise HTTPException(500, "generator.py not found - run from the backend/ directory in the lab VM")
    return {"ok": True, "pid": _generator_proc.pid, "technique": req.technique}


@app.post("/api/generator/stop", dependencies=[auth_dep])
async def generator_stop(request: Request):
    global _generator_proc
    if not _generator_proc or _generator_proc.poll() is not None:
        raise HTTPException(409, "generator not running")
    _generator_proc.terminate()
    audit("generator_stop", request)
    return {"ok": True}


# ------------------------------------------------------------- thresholds --
@app.get("/api/thresholds", dependencies=[auth_dep])
async def get_thresholds():
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(select(Threshold))).scalars().all()
        return {r.key: {"value": r.value, "description": r.description} for r in rows}


@app.put("/api/thresholds", dependencies=[auth_dep])
async def put_threshold(req: ThresholdUpdate, request: Request):
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            update(Threshold).where(Threshold.key == req.key).values(value=req.value)
        )
        await session.commit()
        if result.rowcount == 0:
            raise HTTPException(404, f"unknown threshold key '{req.key}'")

    # Live-apply to whichever detector component actually reads this key.
    # NOTE: this used to unconditionally write into
    # engine.stat_detector.t[req.key], which silently no-oped for
    # 'alert_score' and 'ml_contamination' — neither lives in that dict, so
    # tuning either from the Control page never had any effect. Route each
    # key to the component that actually consumes it.
    if req.key == "alert_score":
        engine.alert_manager.alert_threshold = req.value
    elif req.key == "ml_contamination":
        engine.ml_detector.contamination = req.value
    else:
        engine.stat_detector.t[req.key] = req.value

    audit("threshold_update", request, key=req.key, value=req.value)
    return {"ok": True, "key": req.key, "value": req.value}


# ------------------------------------------------------------------ report --
@app.get("/api/report", dependencies=[auth_dep])
async def full_report():
    async with AsyncSessionLocal() as session:
        flows = (await session.execute(select(Flow).order_by(Flow.created_at.desc()).limit(500))).scalars().all()
        alerts = (await session.execute(select(Alert).order_by(Alert.created_at.desc()).limit(500))).scalars().all()
    return {
        "generated_at": time.time(),
        "totals": engine.totals,
        "flows": [
            {
                "id": f.id, "src": f"{f.src_ip}:{f.src_port}", "dst": f"{f.dst_ip}:{f.dst_port}",
                "protocol": f.ndpi_protocol, "packets": f.packets, "bytes": f.bytes,
                "anomaly_score": f.anomaly_score, "is_covert": f.is_covert,
            }
            for f in flows
        ],
        "alerts": [
            {
                "id": a.id, "flow_id": a.flow_id, "covert_type": a.covert_type,
                "final_score": a.final_score, "confidence": a.confidence,
                "reason": a.reason, "recommendation": a.recommendation,
            }
            for a in alerts
        ],
    }


# --------------------------------------------------------------- ws-ticket --
@app.post("/api/ws-ticket", dependencies=[auth_dep])
async def ws_ticket():
    """Exchanges the long-lived API key (sent as X-API-Key, checked by
    auth_dep above) for a random, single-use, 30s-lived ticket. The
    frontend uses this instead of putting the real key in the /ws URL,
    keeping the durable secret out of browser history / access logs."""
    return {"ticket": mint_ws_ticket(), "expires_in_s": 30}


# --------------------------------------------------------------- websocket --
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    if not await require_api_key_ws(websocket):
        await websocket.close(code=4401)
        return
    await ws_manager.connect(websocket)
    try:
        while True:
            # clients don't need to send anything; keep the connection open
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
