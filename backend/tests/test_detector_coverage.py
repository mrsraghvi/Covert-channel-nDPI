from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "detection"))

from alert_manager import AlertManager
from feature_extractor import FlowFeatures, extract_features, shannon_entropy
from generator.generator import DEFAULT_MESSAGE, b32
from statistical_detector import StatisticalDetector
from app.schemas import GeneratorStartRequest


def shannon_entropy_text(value: str) -> float:
    return shannon_entropy(value)


def generator_signature_flows() -> dict[str, dict]:
    encoded_timing = "".join(f"{byte:08b}" for byte in DEFAULT_MESSAGE.encode())
    timing_intervals = [
        50.0 if bit == "0" else 150.0
        for bit in encoded_timing[:64]
    ]
    timing_bimodal = extract_features({"iat_samples": timing_intervals}).iat_bimodal

    dns_encoded = b32(DEFAULT_MESSAGE.encode())
    dns_label = dns_encoded[:40]
    dns_host = f"{dns_label}.0000.tunnel.test.local"

    http_encoded = base64.b64encode(DEFAULT_MESSAGE.encode()).decode()
    http_user_agent = f"Mozilla/5.0 (compatible; X-{http_encoded}-sync)"

    icmp_payload = DEFAULT_MESSAGE.encode() + bytes(
        (index * 73 + 19) % 256
        for index in range(300 - len(DEFAULT_MESSAGE))
    )

    return {
        "TIMING": {
            "protocol": "TCP",
            "packets": 65,
            "iat_bimodal": timing_bimodal,
        },
        "DNS": {
            "protocol": "DNS",
            "dns_query": dns_host,
            "dns_qlen": len(dns_host),
            "dns_entropy": shannon_entropy_text(dns_label),
        },
        "HTTP": {
            "protocol": "HTTP",
            "http_user_agent": http_user_agent,
            "http_ua_entropy": shannon_entropy_text(http_user_agent),
            "http_url": "/sync",
        },
        "ICMP": {
            "protocol": "ICMP",
            "icmp_payload_len": len(icmp_payload),
            "icmp_payload_entropy": shannon_entropy(icmp_payload),
            "payload_entropy": shannon_entropy(icmp_payload),
        },
    }


class DetectorCoverageTests(unittest.TestCase):
    def test_default_generator_signatures_raise_matching_alerts(self):
        detector = StatisticalDetector()
        manager = AlertManager()
        signatures = generator_signature_flows()

        for flow_id, (technique, raw_flow) in enumerate(signatures.items(), start=1):
            with self.subTest(technique=technique):
                features: FlowFeatures = extract_features(raw_flow)
                result = detector.evaluate(features)
                alert = manager.evaluate(
                    flow_id=flow_id,
                    covert_type=result.covert_type,
                    stat_score=result.score,
                    ml_score=0.0,
                    reasons=result.reasons,
                )

                self.assertGreaterEqual(result.score, 0.40 / 0.60)
                self.assertEqual(result.covert_type, technique)
                self.assertIsNotNone(alert)
                self.assertEqual(alert.covert_type, technique)
                self.assertTrue(any(reason.startswith(f"[{technique}]") for reason in result.reasons))

    def test_generator_default_http_signature_crosses_heuristic_thresholds(self):
        flow = generator_signature_flows()["HTTP"]
        features = extract_features(flow)

        self.assertEqual(GeneratorStartRequest().message, DEFAULT_MESSAGE)
        self.assertGreater(features.http_ua_len, 80)
        self.assertGreater(features.http_ua_entropy, 4.5)

    def test_c_engine_bimodal_feature_is_consumed_without_raw_iat_samples(self):
        flow = generator_signature_flows()["TIMING"]
        self.assertNotIn("iat_samples", flow)

        features = extract_features(flow)

        self.assertGreater(features.iat_bimodal, 0.70)

    def test_ordinary_low_signal_traffic_does_not_raise_a_rule_alert(self):
        features = extract_features({
            "protocol": "HTTP",
            "packets": 8,
            "iat_samples": [20.0, 24.0, 19.0, 23.0, 21.0, 25.0, 18.0],
            "http_user_agent": "Mozilla/5.0",
            "http_ua_entropy": shannon_entropy_text("Mozilla/5.0"),
            "http_url": "/index.html",
            "dns_qlen": 15,
            "dns_entropy": 2.5,
            "icmp_payload_len": 32,
            "icmp_payload_entropy": 4.5,
            "payload_entropy": 4.5,
        })

        result = StatisticalDetector().evaluate(features)
        alert = AlertManager().evaluate(
            flow_id=100,
            covert_type=result.covert_type,
            stat_score=result.score,
            ml_score=0.0,
            reasons=result.reasons,
        )

        self.assertEqual(result.score, 0.0)
        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
