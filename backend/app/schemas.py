from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

# Network interface names on Linux are capped at 15 chars (IFNAMSIZ-1) and
# only ever contain these characters — anything else is not a real iface.
_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,15}$")

# Known, whitelisted threshold keys — kept in sync with Alembic's threshold
# seed rows (the full set the system actually persists/reads), not just the
# subset the current Control page happens to expose sliders for. A narrower
# list here would silently reject legitimate updates to keys the UI doesn't
# surface yet but the API/DB already support.
KNOWN_THRESHOLD_KEYS = {
    "entropy_high",
    "dns_label_entropy",
    "dns_label_len",
    "dns_qps",
    "iat_cv_low",
    "iat_autocorr",
    "http_ua_entropy",
    "http_url_entropy",
    "icmp_payload_len",
    "icmp_payload_entropy",
    "alert_score",
    "ml_contamination",
}


class FlowOut(BaseModel):
    id: int
    flow_uid: int
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: str
    dst_port: Optional[int] = None
    l4_proto: Optional[str] = None
    ndpi_protocol: Optional[str] = None
    packets: int
    bytes: int
    duration_ms: int
    iat_mean: Optional[float] = None
    iat_cv: Optional[float] = None
    payload_entropy: Optional[float] = None
    dns_query: Optional[str] = None
    dns_entropy: Optional[float] = None
    http_host: Optional[str] = None
    covert_flags: int = 0
    anomaly_score: float = 0
    is_covert: bool = False
    blocked: bool = False
    created_at: datetime

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    id: int
    flow_id: int
    covert_type: str
    stat_score: float
    ml_score: float
    final_score: float
    confidence: str
    reason: Optional[str] = None
    recommendation: Optional[str] = None
    acknowledged: bool = False
    created_at: datetime
    # Denormalized from the joined flow so the frontend can offer a "block
    # this source" action directly from an alert row without a second
    # round-trip. None only if the parent flow was somehow deleted.
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    class Config:
        from_attributes = True


class StatsOut(BaseModel):
    total_flows: int
    total_alerts: int
    covert_flows: int
    active_capture: bool
    protocol_distribution: dict[str, int]
    confidence_distribution: dict[str, int]
    covert_type_distribution: dict[str, int]
    avg_entropy: float
    packets_per_sec: float
    bytes_per_sec: float


class ThresholdUpdate(BaseModel):
    key: str
    value: float = Field(ge=0.0, le=1000.0)

    @field_validator("key")
    @classmethod
    def key_must_be_known(cls, v: str) -> str:
        if v not in KNOWN_THRESHOLD_KEYS:
            raise ValueError(
                f"unknown threshold key {v!r}; must be one of {sorted(KNOWN_THRESHOLD_KEYS)}"
            )
        return v


class CaptureStartRequest(BaseModel):
    interface: str = Field(default="eth0")
    bpf_filter: Optional[str] = Field(default=None, max_length=256)
    mode: Literal["simulated", "live"] = Field(default="simulated")

    @field_validator("interface")
    @classmethod
    def interface_must_be_safe(cls, v: str) -> str:
        if not _IFACE_RE.match(v):
            raise ValueError(
                "interface must look like a real Linux network interface name "
                "(letters/digits/._- , max 15 chars)"
            )
        return v

    @field_validator("bpf_filter")
    @classmethod
    def bpf_filter_no_control_chars(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if any(ord(c) < 0x20 for c in v):
            raise ValueError("bpf_filter must not contain control characters")
        return v


class GeneratorStartRequest(BaseModel):
    technique: Literal["timing", "dns", "http", "icmp", "all"] = Field(default="all")
    target: str = Field(default="127.0.0.1")
    message: str = Field(default="covertscope-lab-test-payload-12345", max_length=256)
    duration_s: int = Field(default=30, ge=1, le=300)

    @field_validator("target")
    @classmethod
    def target_must_be_loopback(cls, v: str) -> str:
        # generator.py itself refuses non-loopback targets (its own,
        # load-bearing safety control) — this is defense-in-depth so the
        # backend rejects an unsafe request before ever spawning the
        # subprocess, and returns a clear 422 instead of a subprocess exit
        # code the caller has to go dig up.
        try:
            addr = ipaddress.ip_address(v)
        except ValueError as e:
            raise ValueError(
                "target must be a literal loopback IP (127.0.0.1 or ::1); "
                "hostnames are not accepted here"
            ) from e
        if not addr.is_loopback:
            raise ValueError("target must be loopback (127.0.0.1 / ::1) — this is a self-test harness only")
        return v


class BlockCreate(BaseModel):
    """Raise (or refresh) a soft/advisory block on an IP. See BlockedIP's
    docstring in database.py for what this does and doesn't do."""
    ip: str
    reason: Optional[str] = Field(default=None, max_length=512)
    alert_id: Optional[int] = None

    @field_validator("ip")
    @classmethod
    def ip_must_be_valid(cls, v: str) -> str:
        # Reject anything that isn't a literal IP address before it ever
        # reaches a DB row or an in-memory set key — no hostnames, no CIDR,
        # no stray whitespace/control characters riding along.
        try:
            ipaddress.ip_address(v.strip())
        except ValueError as e:
            raise ValueError("ip must be a literal IPv4 or IPv6 address") from e
        return v.strip()

    @field_validator("reason")
    @classmethod
    def reason_no_control_chars(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if any(ord(c) < 0x20 and c not in "\t" for c in v):
            raise ValueError("reason must not contain control characters")
        return v


class BlockOut(BaseModel):
    id: int
    ip: str
    reason: Optional[str] = None
    alert_id: Optional[int] = None
    active: bool = True
    created_at: datetime

    class Config:
        from_attributes = True
