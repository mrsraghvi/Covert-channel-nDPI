"""
simulator.py
Generates synthetic flow *metadata* (packet counts, IATs, entropy figures,
DNS/HTTP/ICMP summary fields) that mimics what the real nDPI C engine would
emit — without touching a network interface or crafting real packets.

Purpose: let the dashboard, detectors, and API be fully exercised in local
dev (laptop, CI, this sandbox) where raw-socket capture isn't available or
authorized. In the lab VM, this is swapped out for the real TCP:9999 feed
from ndpi-engine/covert_channel_detector.
"""
from __future__ import annotations

import asyncio
import random
import string
import time

BENIGN_PROTOCOLS = ["HTTPS", "QUIC", "TLS", "NTP", "SSH", "DNS", "HTTP"]
DEFAULT_COVERT_RATIO = 0.05
MIN_FLOW_INTERVAL_SECONDS = 2.0
MAX_FLOW_INTERVAL_SECONDS = 4.0


def _rand_ip(private: bool = True) -> str:
    if private:
        return f"192.168.{random.randint(0,5)}.{random.randint(2,254)}"
    return f"{random.randint(20,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _rand_string(n: int, high_entropy: bool = False) -> str:
    if high_entropy:
        alphabet = string.ascii_letters + string.digits + "+/="
    else:
        alphabet = "abcdefghijklmnopqrstuvwxyz"
    return "".join(random.choice(alphabet) for _ in range(n))


def benign_flow(flow_id: int) -> dict:
    proto = random.choice(BENIGN_PROTOCOLS)
    packets = random.randint(4, 60)
    duration_ms = random.randint(200, 8000)
    avg_len = random.uniform(300, 1400)
    flow = {
        "type": "flow",
        "flow_id": flow_id,
        "src": f"{_rand_ip()}:{random.randint(1024,65000)}",
        "dst": f"{_rand_ip(private=False)}:{443 if proto in ('HTTPS','TLS','QUIC') else 80}",
        "protocol": proto,
        "ndpi_proto_id": abs(hash(proto)) % 200,
        "l4_proto": "UDP" if proto in ("QUIC", "NTP", "DNS") else "TCP",
        "packets": packets,
        "bytes": int(packets * avg_len),
        "duration_ms": duration_ms,
        "iat_mean": duration_ms / max(packets, 1) * random.uniform(0.7, 1.4),
        "iat_variance": random.uniform(50, 900),
        "payload_entropy": random.uniform(2.5, 6.0),
        "covert_flags": 0,
        "ts": int(time.time() * 1000),
    }
    if proto == "DNS":
        flow["dns_query"] = f"{_rand_string(random.randint(4, 15))}.example.com"
        flow["dns_entropy"] = random.uniform(1.5, 3.2)
        flow["dns_qlen"] = len(flow["dns_query"])
        flow["dns_qps"] = random.uniform(0.2, 4.0)
    if proto in ("HTTP",):
        flow["http_host"] = "cdn.example.com"
        flow["http_user_agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        flow["http_url"] = "/assets/app.js"
        flow["http_ua_entropy"] = random.uniform(3.0, 4.0)
    return flow


def covert_flow(flow_id: int, technique: str | None = None) -> dict:
    """Synthetic flow whose *statistics* resemble a covert channel — used
    only to validate the detector's math, not a working exfil tool."""
    technique = technique or random.choice(["timing", "dns", "http", "icmp"])
    base = {
        "type": "flow",
        "flow_id": flow_id,
        "src": f"{_rand_ip()}:{random.randint(1024,65000)}",
        "covert_flags": 1,
        "ts": int(time.time() * 1000),
    }

    if technique == "timing":
        packets = random.randint(20, 80)
        # near-constant IAT -> low CV, high autocorrelation, drives detector
        base.update({
            "dst": f"{_rand_ip(private=False)}:443",
            "protocol": "TLS",
            "ndpi_proto_id": 91,
            "l4_proto": "TCP",
            "packets": packets,
            "bytes": packets * random.randint(64, 128),
            "duration_ms": packets * 100,
            "iat_mean": 100.0,
            "iat_variance": random.uniform(0.5, 4.0),
            "iat_cv": random.uniform(0.005, 0.03),
            "iat_autocorr1": random.uniform(0.85, 0.98),
            "payload_entropy": random.uniform(3.0, 5.0),
        })
    elif technique == "dns":
        label = _rand_string(random.randint(65, 100), high_entropy=True)
        base.update({
            "dst": f"{_rand_ip(private=False)}:53",
            "protocol": "DNS",
            "ndpi_proto_id": 5,
            "l4_proto": "UDP",
            "packets": random.randint(30, 200),
            "bytes": random.randint(4000, 30000),
            "duration_ms": random.randint(3000, 15000),
            "dns_query": f"{label}.tunnel.research.local",
            "dns_entropy": random.uniform(3.9, 4.6),
            "dns_qlen": len(label),
            "dns_qps": random.uniform(16, 40),
        })
    elif technique == "http":
        ua = "X-" + _rand_string(90, high_entropy=True)
        base.update({
            "dst": f"{_rand_ip(private=False)}:80",
            "protocol": "HTTP",
            "ndpi_proto_id": 7,
            "l4_proto": "TCP",
            "packets": random.randint(10, 40),
            "bytes": random.randint(2000, 9000),
            "duration_ms": random.randint(500, 4000),
            "http_host": "cdn-assets-relay.example.net",
            "http_user_agent": ua,
            "http_url": "/api/v1/sync?token=" + _rand_string(140, high_entropy=True),
            "http_ua_entropy": random.uniform(4.6, 5.4),
        })
    else:  # icmp
        payload_len = random.randint(200, 900)
        base.update({
            "dst": f"{_rand_ip(private=False)}:0",
            "protocol": "ICMP",
            "ndpi_proto_id": 3,
            "l4_proto": "ICMP",
            "packets": random.randint(5, 30),
            "bytes": payload_len * random.randint(5, 30),
            "duration_ms": random.randint(500, 6000),
            "icmp_payload_len": payload_len,
            "icmp_payload_entropy": random.uniform(6.2, 7.6),
            "payload_entropy": random.uniform(6.2, 7.6),
        })
    return base


async def run_simulator(engine, stop_event: asyncio.Event, covert_ratio: float = DEFAULT_COVERT_RATIO):
    """Feed synthetic flows at a paced rate until stop_event is set."""
    flow_id = int(time.time())
    generated_flows = 0
    covert_interval = round(1 / covert_ratio) if covert_ratio > 0 else None
    while not stop_event.is_set():
        flow_id += 1
        generated_flows += 1
        if covert_interval and generated_flows % covert_interval == 0:
            record = covert_flow(flow_id)
        else:
            record = benign_flow(flow_id)
        await engine.ingest(record)
        await asyncio.sleep(random.uniform(MIN_FLOW_INTERVAL_SECONDS, MAX_FLOW_INTERVAL_SECONDS))
