"""
alert_manager.py
Combines the statistical detector's rule score and the ML detector's
anomaly score into a single final_score, assigns a confidence tier,
generates a human-readable recommendation, and deduplicates repeated
alerts for the same flow within a cooldown window.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

STAT_WEIGHT = 0.6
ML_WEIGHT = 0.4
ALERT_THRESHOLD = 0.40

RECOMMENDATIONS = {
    "TIMING": "Investigate the endpoint for scheduled beaconing. Compare inter-arrival "
              "times against known C2 jitter profiles; consider blocking or rate-limiting "
              "the flow and inspecting the host for persistence mechanisms.",
    "DNS": "Likely DNS tunneling. Review the queried domain's registration and TTL, "
           "check for high-volume TXT/NULL record use, and consider forcing DNS "
           "through an inspected resolver or blocking direct outbound UDP/53.",
    "HTTP": "Header-based covert channel suspected. Inspect User-Agent/custom header "
            "values for encoded payloads, and correlate with the destination's TLS "
            "certificate reputation and hosting history.",
    "ICMP": "Oversized/high-entropy ICMP payload suggests data exfiltration or C2 over "
            "ping. Rate-limit or block outbound ICMP where not operationally required, "
            "and capture a pcap sample for offline payload analysis.",
    "GENERIC": "High-entropy payload detected without a specific covert-channel "
               "signature. Treat as encrypted/compressed traffic of unknown origin and "
               "correlate with endpoint telemetry.",
}


def confidence_tier(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.45:
        return "MEDIUM"
    return "LOW"


@dataclass
class Alert:
    flow_id: int
    covert_type: str
    stat_score: float
    ml_score: float
    final_score: float
    confidence: str
    reason: str
    recommendation: str
    ts: float = field(default_factory=time.time)


class AlertManager:
    def __init__(self, cooldown_s: float = 30.0, alert_threshold: float = ALERT_THRESHOLD):
        self.cooldown_s = cooldown_s
        self.alert_threshold = alert_threshold
        self._last_alert_by_flow: dict[int, float] = {}

    def combine(self, stat_score: float, ml_score: float) -> float:
        return round(STAT_WEIGHT * stat_score + ML_WEIGHT * ml_score, 4)

    def evaluate(
        self,
        flow_id: int,
        covert_type: str | None,
        stat_score: float,
        ml_score: float,
        reasons: list[str],
    ) -> Alert | None:
        final_score = self.combine(stat_score, ml_score)
        if final_score < self.alert_threshold:
            return None

        now = time.time()
        last = self._last_alert_by_flow.get(flow_id, 0)
        if now - last < self.cooldown_s:
            return None  # deduplicated
        self._last_alert_by_flow[flow_id] = now

        ctype = covert_type or "GENERIC"
        return Alert(
            flow_id=flow_id,
            covert_type=ctype,
            stat_score=stat_score,
            ml_score=ml_score,
            final_score=final_score,
            confidence=confidence_tier(final_score),
            reason="; ".join(reasons) if reasons else "combined stat+ML anomaly",
            recommendation=RECOMMENDATIONS.get(ctype, RECOMMENDATIONS["GENERIC"]),
        )
