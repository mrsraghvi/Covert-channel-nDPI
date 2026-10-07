#!/usr/bin/env python3
"""
generator.py — CovertScope lab-only test traffic generator.

Purpose: produce traffic with the *statistical signatures* of known covert
channel techniques (timing, DNS-label encoding, HTTP header stuffing, ICMP
payload stuffing) so you can validate that the detection engine actually
catches them — the same way an IDS/IPS test suite replays known-bad traffic
against Snort/Suricata rules.

Hard safety constraint: this script refuses to run against anything other
than the loopback interface (127.0.0.1 / ::1). It is a self-test harness,
not a general-purpose exfiltration or tunneling tool, and it will not send
a single packet anywhere else no matter what target is supplied.

Usage (inside your isolated lab VM, with the backend + nDPI engine running):
    python3 generator.py --technique all --message "covertscope-test"
    python3 generator.py --technique dns  --dns-domain tunnel.test.local
    python3 generator.py --technique icmp --icmp-chunk 300     # needs root for raw ICMP
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import random
import socket
import string
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

LOOPBACK_ONLY = {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}
LOG_PATH = Path(__file__).with_name("transmissions.jsonl")
# The default sample is long enough to cross the HTTP detector's default
# User-Agent length threshold while keeping the generator useful as a smoke test.
DEFAULT_MESSAGE = "covertscope-lab-test-payload-12345"


def assert_loopback(target: str) -> str:
    """Refuse to run against anything but loopback. This is the load-bearing
    safety control for this script — it must not be bypassable via CLI
    flags, env vars, or DNS tricks, so we resolve first and re-check."""
    try:
        resolved = socket.gethostbyname(target)
        addr = ipaddress.ip_address(resolved)
    except (socket.gaierror, ValueError) as e:
        print(f"[refused] could not resolve/parse target '{target}': {e}", file=sys.stderr)
        sys.exit(2)

    if addr not in LOOPBACK_ONLY and not addr.is_loopback:
        print(
            f"[refused] target '{target}' resolves to {addr}, which is not loopback. "
            f"This generator only sends traffic to 127.0.0.1/::1 — it is a detector "
            f"self-test harness, not an exfiltration tool.",
            file=sys.stderr,
        )
        sys.exit(2)
    return str(addr)


def log_transmission(technique: str, target: str, message_len: int, chunks: int, success: bool):
    entry = {
        "technique": technique,
        "target": target,
        "message_len": message_len,
        "chunks": chunks,
        "success": success,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def b32(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=").lower()


# --------------------------------------------------------------------- #
# Technique: TIMING — encode bits as inter-packet delay (50ms='0', 150ms='1')
# --------------------------------------------------------------------- #
def run_timing(target: str, message: str, port: int = 9797):
    bits = "".join(f"{b:08b}" for b in message.encode())
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((target, port))
    except OSError:
        print(f"[timing] no listener on {target}:{port} — sending as UDP beacons instead")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[timing] encoding {len(bits)} bits as packet inter-arrival delays")
    for bit in bits:
        delay = 0.150 if bit == "1" else 0.050
        try:
            sock.sendto(b"\x00", (target, port)) if sock.type == socket.SOCK_DGRAM else sock.send(b"\x00")
        except OSError:
            pass
        time.sleep(delay)
    sock.close()
    log_transmission("timing", target, len(message), len(bits), True)
    print(f"[timing] done — {len(bits)} timed packets sent to {target}:{port}")


# --------------------------------------------------------------------- #
# Technique: DNS — base32 payload in subdomain labels
# --------------------------------------------------------------------- #
def run_dns(target: str, message: str, dns_domain: str, port: int = 5353):
    """Sends crafted UDP packets shaped like DNS queries with high-entropy
    subdomain labels to a *local* test port (not real port 53 resolution —
    this validates the detector's label-length/entropy heuristics without
    touching the system resolver or any real DNS infrastructure)."""
    encoded = b32(message.encode())
    chunk_size = 40
    chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[dns] sending {len(chunks)} label-encoded chunks to {target}:{port} (loopback test port, not real DNS)")
    for i, chunk in enumerate(chunks):
        label = f"{chunk}.{i:04x}.{dns_domain}"
        # Minimal fake "DNS query"-shaped payload: just the label, newline-terminated.
        # This intentionally mimics the query_len/entropy signature nDPI+the
        # statistical detector look for, without going near a real resolver.
        sock.sendto(label.encode(), (target, port))
        time.sleep(random.uniform(0.02, 0.08))
    sock.close()
    log_transmission("dns", target, len(message), len(chunks), True)
    print(f"[dns] done — {len(chunks)} chunks sent")


# --------------------------------------------------------------------- #
# Technique: HTTP — base64 payload in User-Agent / custom header
# --------------------------------------------------------------------- #
def run_http(target: str, message: str, port: int = 8899):
    encoded = base64.b64encode(message.encode()).decode()
    ua = f"Mozilla/5.0 (compatible; X-{encoded}-sync)"
    request = (
        f"GET /sync HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"User-Agent: {ua}\r\n"
        f"X-Session-Token: {encoded}\r\n"
        f"Connection: close\r\n\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((target, port))
        sock.send(request.encode())
        try:
            sock.recv(1024)
        except OSError:
            pass
        success = True
    except OSError as e:
        print(f"[http] no listener on {target}:{port} ({e}) — request was still constructed for logging")
        success = False
    finally:
        sock.close()
    log_transmission("http", target, len(message), 1, success)
    print(f"[http] done — {'sent' if success else 'attempted'} header-encoded request to {target}:{port}")


# --------------------------------------------------------------------- #
# Technique: ICMP — oversized/high-entropy echo payload
# --------------------------------------------------------------------- #
def run_icmp(target: str, message: str, chunk_size: int = 300):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("[icmp] raw ICMP sockets require root/CAP_NET_RAW — skipping. "
              "Run with sudo inside the lab VM to exercise this technique.")
        log_transmission("icmp", target, len(message), 0, False)
        return

    data = message.encode() + bytes(random.getrandbits(8) for _ in range(max(0, chunk_size - len(message))))
    header = bytes([8, 0, 0, 0, 0, 1, 0, 1])  # type=echo, code=0, checksum placeholder, id=1, seq=1
    checksum = _icmp_checksum(header + data)
    packet = bytes([8, 0, (checksum >> 8) & 0xFF, checksum & 0xFF, 0, 1, 0, 1]) + data

    print(f"[icmp] sending {len(packet)}B echo payload to {target} (entropy signature test)")
    sock.sendto(packet, (target, 0))
    sock.close()
    log_transmission("icmp", target, len(message), 1, True)
    print("[icmp] done")


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


# --------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(description="CovertScope lab-only covert channel test generator (loopback only).")
    parser.add_argument("--target", default="127.0.0.1", help="Must resolve to loopback (127.0.0.1 / ::1).")
    parser.add_argument("--technique", choices=["timing", "dns", "http", "icmp", "all"], default="all")
    parser.add_argument("--message", default=DEFAULT_MESSAGE)
    parser.add_argument("--dns-domain", default="tunnel.test.local")
    parser.add_argument("--icmp-chunk", type=int, default=300)
    parser.add_argument("--duration", type=int, default=0, help="Unused hook for the API wrapper; techniques run once.")
    args = parser.parse_args()

    target = assert_loopback(args.target)
    print(f"=== CovertScope generator — techniques run only against loopback ({target}) ===")

    techniques = ["timing", "dns", "http", "icmp"] if args.technique == "all" else [args.technique]
    for t in techniques:
        if t == "timing":
            run_timing(target, args.message)
        elif t == "dns":
            run_dns(target, args.message, args.dns_domain)
        elif t == "http":
            run_http(target, args.message)
        elif t == "icmp":
            run_icmp(target, args.message, args.icmp_chunk)

    print("=== done — check the Flows/Alerts pages in the dashboard for detections ===")


if __name__ == "__main__":
    main()
