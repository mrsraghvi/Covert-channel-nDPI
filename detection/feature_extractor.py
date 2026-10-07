"""
feature_extractor.py
Shared math helpers for turning a raw flow record (as emitted by the nDPI
C engine, or by the traffic simulator) into the feature vector consumed by
the statistical and ML detectors.

No network capture happens here — this module is pure math over already
extracted flow metadata (IATs, payload bytes, DNS labels, etc).
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional


def shannon_entropy(data: bytes | str) -> float:
    """Shannon entropy in bits/symbol over the given byte string or text."""
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def coefficient_of_variation(values: list[float]) -> float:
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance) / mean


def autocorrelation_lag1(values: list[float]) -> float:
    n = len(values)
    if n < 3:
        return 0.0
    mean = sum(values) / n
    denom = sum((v - mean) ** 2 for v in values)
    if denom == 0:
        return 0.0
    numer = sum((values[i] - mean) * (values[i + 1] - mean) for i in range(n - 1))
    return numer / denom


def bimodal_ratio(values: list[float], tolerance: float = 0.15) -> float:
    """Fraction of samples that fall near one of the two dominant clusters.
    High values suggest binary (0/1) timing encodings."""
    if len(values) < 4:
        return 0.0
    sorted_vals = sorted(values)
    lo_center = sorted_vals[len(sorted_vals) // 8]
    hi_center = sorted_vals[-max(1, len(sorted_vals) // 8)]
    if hi_center == lo_center:
        return 0.0
    span = hi_center - lo_center
    near = sum(
        1
        for v in values
        if abs(v - lo_center) <= tolerance * span or abs(v - hi_center) <= tolerance * span
    )
    return near / len(values)


@dataclass
class FlowFeatures:
    """21-dimensional feature vector used by the ML detector, plus the
    human-readable fields used by the statistical/rule-based detector."""

    # timing
    iat_mean: float = 0.0
    iat_variance: float = 0.0
    iat_cv: float = 0.0
    iat_autocorr1: float = 0.0
    iat_bimodal: float = 0.0

    # volumetrics
    packets: int = 0
    bytes: int = 0
    duration_ms: int = 0
    avg_pkt_len: float = 0.0
    pkt_rate: float = 0.0
    byte_rate: float = 0.0

    # payload
    payload_entropy: float = 0.0

    # DNS
    dns_entropy: float = 0.0
    dns_qlen: int = 0
    dns_qps: float = 0.0

    # HTTP
    http_ua_entropy: float = 0.0
    http_ua_len: int = 0
    http_url_entropy: float = 0.0
    http_url_len: int = 0

    # ICMP
    icmp_payload_len: int = 0
    icmp_payload_entropy: float = 0.0

    protocol: str = "Unknown"

    def to_vector(self) -> list[float]:
        """Fixed-order 21-feature vector for the Isolation Forest."""
        return [
            self.iat_mean,
            self.iat_variance,
            self.iat_cv,
            self.iat_autocorr1,
            self.iat_bimodal,
            float(self.packets),
            float(self.bytes),
            float(self.duration_ms),
            self.avg_pkt_len,
            self.pkt_rate,
            self.byte_rate,
            self.payload_entropy,
            self.dns_entropy,
            float(self.dns_qlen),
            self.dns_qps,
            self.http_ua_entropy,
            float(self.http_ua_len),
            self.http_url_entropy,
            float(self.http_url_len),
            float(self.icmp_payload_len),
            self.icmp_payload_entropy,
        ]

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "iat_mean", "iat_variance", "iat_cv", "iat_autocorr1", "iat_bimodal",
            "packets", "bytes", "duration_ms", "avg_pkt_len", "pkt_rate", "byte_rate",
            "payload_entropy", "dns_entropy", "dns_qlen", "dns_qps",
            "http_ua_entropy", "http_ua_len", "http_url_entropy", "http_url_len",
            "icmp_payload_len", "icmp_payload_entropy",
        ]


def extract_features(flow: dict) -> FlowFeatures:
    """Build a FlowFeatures object from a raw flow dict (as produced by the
    C engine's JSON export or the simulator)."""
    iats: list[float] = flow.get("iat_samples", [])
    duration_ms = flow.get("duration_ms", 0) or 1
    packets = flow.get("packets", 0)
    nbytes = flow.get("bytes", 0)

    f = FlowFeatures(
        iat_mean=flow.get("iat_mean", sum(iats) / len(iats) if iats else 0.0),
        iat_variance=flow.get("iat_variance", 0.0),
        iat_cv=flow.get("iat_cv", coefficient_of_variation(iats)),
        iat_autocorr1=flow.get("iat_autocorr1", autocorrelation_lag1(iats)),
        iat_bimodal=flow.get("iat_bimodal", bimodal_ratio(iats)),
        packets=packets,
        bytes=nbytes,
        duration_ms=duration_ms,
        avg_pkt_len=(nbytes / packets) if packets else 0.0,
        pkt_rate=packets / (duration_ms / 1000.0) if duration_ms else 0.0,
        byte_rate=nbytes / (duration_ms / 1000.0) if duration_ms else 0.0,
        payload_entropy=flow.get("payload_entropy", 0.0),
        dns_entropy=flow.get("dns_entropy", 0.0),
        dns_qlen=flow.get("dns_qlen", 0),
        dns_qps=flow.get("dns_qps", 0.0),
        http_ua_entropy=flow.get("http_ua_entropy", 0.0),
        http_ua_len=len(flow.get("http_user_agent") or ""),
        http_url_entropy=shannon_entropy(flow.get("http_url", "")) if flow.get("http_url") else 0.0,
        http_url_len=len(flow.get("http_url") or ""),
        icmp_payload_len=flow.get("icmp_payload_len", 0),
        icmp_payload_entropy=flow.get("icmp_payload_entropy", 0.0),
        protocol=flow.get("ndpi_protocol", flow.get("protocol", "Unknown")),
    )
    return f
