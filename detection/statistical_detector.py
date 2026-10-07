"""
statistical_detector.py
Rule-based covert channel detector. Implements the five detection families
described in the design doc: entropy analysis, IAT analysis, DNS tunnel
detection, HTTP covert detection, and ICMP covert detection.

Each detector returns a (score 0..1, list[reason]) pair. Scores are combined
by AlertManager together with the ML detector's anomaly score.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from feature_extractor import FlowFeatures


@dataclass
class StatResult:
    score: float = 0.0
    covert_type: str | None = None
    reasons: list[str] = field(default_factory=list)


class StatisticalDetector:
    def __init__(self, thresholds: dict | None = None):
        # sane defaults, mirrors database/schema.sql seed values
        self.t = {
            "entropy_high": 7.2,
            "dns_label_entropy": 3.8,
            "dns_label_len": 60,
            "dns_qps": 15,
            "iat_cv_low": 0.05,
            "iat_autocorr": 0.80,
            "http_ua_entropy": 4.5,
            "http_ua_len": 80,
            "http_url_entropy": 4.8,
            "http_url_len": 128,
            "icmp_payload_len": 64,
            "icmp_payload_entropy": 6.0,
        }
        if thresholds:
            self.t.update(thresholds)

    def evaluate(self, f: FlowFeatures) -> StatResult:
        checks = [
            self._timing_check(f),
            self._dns_check(f),
            self._http_check(f),
            self._icmp_check(f),
            self._entropy_check(f),
        ]
        best = max(checks, key=lambda r: r.score)
        # merge reasons from any check that also fired, for transparency
        merged_reasons = []
        for c in checks:
            merged_reasons.extend(c.reasons)
        best.reasons = merged_reasons or best.reasons
        return best

    # ---- individual rule families -------------------------------------

    def _timing_check(self, f: FlowFeatures) -> StatResult:
        reasons = []
        score = 0.0
        if f.packets >= 8:
            if 0 < f.iat_cv < self.t["iat_cv_low"]:
                score = max(score, 0.75)
                reasons.append(
                    f"[TIMING] suspiciously regular IAT: cv={f.iat_cv:.4f} < {self.t['iat_cv_low']}"
                )
            if f.iat_autocorr1 > self.t["iat_autocorr"]:
                score = max(score, 0.70)
                reasons.append(
                    f"[TIMING] periodic pattern: autocorr(lag1)={f.iat_autocorr1:.2f} > {self.t['iat_autocorr']}"
                )
            if f.iat_bimodal > 0.70:
                score = max(score, 0.80)
                reasons.append(
                    f"[TIMING] bimodal IAT distribution: {f.iat_bimodal:.0%} of samples in two clusters -> possible binary encoding"
                )
        return StatResult(score=score, covert_type="TIMING" if score else None, reasons=reasons)

    def _dns_check(self, f: FlowFeatures) -> StatResult:
        if f.protocol.upper() != "DNS" and f.dns_qlen == 0:
            return StatResult()
        reasons = []
        score = 0.0
        if f.dns_qlen > self.t["dns_label_len"]:
            score = max(score, 0.65)
            reasons.append(f"[DNS] label length {f.dns_qlen} > {self.t['dns_label_len']}")
        if f.dns_entropy > self.t["dns_label_entropy"]:
            score = max(score, 0.70)
            reasons.append(f"[DNS] label entropy {f.dns_entropy:.2f} > {self.t['dns_label_entropy']}")
        if f.dns_qps > self.t["dns_qps"]:
            score = max(score, 0.60)
            reasons.append(f"[DNS] query rate {f.dns_qps:.1f} qps > {self.t['dns_qps']}")
        if f.dns_qlen > self.t["dns_label_len"] and f.dns_entropy > self.t["dns_label_entropy"]:
            score = 0.90  # both conditions -> high confidence tunnel
            reasons.append("[DNS] combined length+entropy signature strongly indicates tunneling")
        return StatResult(score=score, covert_type="DNS" if score else None, reasons=reasons)

    def _http_check(self, f: FlowFeatures) -> StatResult:
        if f.protocol.upper() not in ("HTTP", "HTTPS", "HTTP_PROXY") and f.http_ua_len == 0 and f.http_url_len == 0:
            return StatResult()
        reasons = []
        score = 0.0
        if f.http_ua_entropy > self.t["http_ua_entropy"] and f.http_ua_len > self.t["http_ua_len"]:
            score = max(score, 0.70)
            reasons.append(
                f"[HTTP] User-Agent entropy {f.http_ua_entropy:.2f} > {self.t['http_ua_entropy']}, len {f.http_ua_len} > {self.t['http_ua_len']}"
            )
        if f.http_url_entropy > self.t["http_url_entropy"] and f.http_url_len > self.t["http_url_len"]:
            score = max(score, 0.72)
            reasons.append(
                f"[HTTP] URL entropy {f.http_url_entropy:.2f} > {self.t['http_url_entropy']}, len {f.http_url_len} > {self.t['http_url_len']}"
            )
        return StatResult(score=score, covert_type="HTTP" if score else None, reasons=reasons)

    def _icmp_check(self, f: FlowFeatures) -> StatResult:
        if f.protocol.upper() != "ICMP" and f.icmp_payload_len == 0:
            return StatResult()
        reasons = []
        score = 0.0
        if f.icmp_payload_len > self.t["icmp_payload_len"]:
            score = max(score, 0.55)
            reasons.append(f"[ICMP] payload {f.icmp_payload_len}B > {self.t['icmp_payload_len']}B standard ping")
        if f.icmp_payload_entropy > self.t["icmp_payload_entropy"]:
            score = max(score, 0.78)
            reasons.append(f"[ICMP] payload entropy {f.icmp_payload_entropy:.2f} > {self.t['icmp_payload_entropy']}")
        return StatResult(score=score, covert_type="ICMP" if score else None, reasons=reasons)

    def _entropy_check(self, f: FlowFeatures) -> StatResult:
        reasons = []
        score = 0.0
        if f.payload_entropy > self.t["entropy_high"]:
            score = 0.60
            reasons.append(f"[ENTROPY] payload entropy {f.payload_entropy:.2f} > {self.t['entropy_high']} bits")
        return StatResult(score=score, covert_type="GENERIC" if score else None, reasons=reasons)
