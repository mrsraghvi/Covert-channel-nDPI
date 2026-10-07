from __future__ import annotations

import io
import socket
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import dpkt

sys.path.append(str(Path(__file__).resolve().parents[2] / "detection"))
from feature_extractor import shannon_entropy


MAX_REPLAY_PACKETS = 100_000
MAX_REPLAY_FLOWS = 5_000
MAX_FLOW_PAYLOAD_SAMPLE = 512
MAX_APP_DATA = 65_536


class PcapReplayError(ValueError):
    pass


@dataclass
class _Flow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    l4_proto: str
    protocol: str
    first_seen: float
    last_seen: float
    packet_times: list[float] = field(default_factory=list)
    payload_sample: bytearray = field(default_factory=bytearray)
    app_data: bytearray = field(default_factory=bytearray)
    icmp_payload_len: int = 0
    bytes: int = 0
    packets: int = 0
    dns_queries: list[str] = field(default_factory=list)
    http_host: str | None = None
    http_user_agent: str | None = None
    http_url: str | None = None

    def add_packet(self, timestamp: float, packet_len: int, payload: bytes) -> None:
        self.packet_times.append(timestamp)
        self.last_seen = timestamp
        self.bytes += packet_len
        self.packets += 1
        if self.l4_proto == "ICMP":
            self.icmp_payload_len += len(payload)
        remaining = MAX_FLOW_PAYLOAD_SAMPLE - len(self.payload_sample)
        if remaining > 0 and payload:
            self.payload_sample.extend(payload[:remaining])
        remaining_app = MAX_APP_DATA - len(self.app_data)
        if remaining_app > 0 and payload:
            self.app_data.extend(payload[:remaining_app])

    def as_ingest_record(self, flow_id: int) -> dict[str, Any]:
        duration_ms = max(0, int((self.last_seen - self.first_seen) * 1000))
        iats = [
            max(0.0, (later - earlier) * 1000)
            for earlier, later in zip(self.packet_times, self.packet_times[1:])
        ]
        dns_query = self.dns_queries[-1] if self.dns_queries else None
        host = self.http_host or (dns_query if self.protocol == "DNS" else None)
        dns_label = (dns_query or "").split(".", 1)[0]
        dns_queries_per_sec = len(self.dns_queries) / max(
            (self.last_seen - self.first_seen), 0.001
        )
        return {
            "flow_id": flow_id,
            "src": _endpoint(self.src_ip, self.src_port),
            "dst": _endpoint(self.dst_ip, self.dst_port),
            "l4_proto": self.l4_proto,
            "protocol": self.protocol,
            "packets": self.packets,
            "bytes": self.bytes,
            "duration_ms": duration_ms,
            "iat_samples": iats,
            "payload_entropy": shannon_entropy(bytes(self.payload_sample)),
            "dns_query": dns_query,
            "dns_entropy": shannon_entropy(dns_label),
            "dns_qlen": len(dns_query or ""),
            "dns_qps": dns_queries_per_sec,
            "http_host": self.http_host,
            "http_user_agent": self.http_user_agent,
            "http_url": self.http_url,
            "icmp_payload_len": self.icmp_payload_len,
            "icmp_payload_entropy": (
                shannon_entropy(bytes(self.payload_sample))
                if self.l4_proto == "ICMP" else 0.0
            ),
        }


def _app_protocol(l4_proto: str, src_port: int, dst_port: int) -> str:
    ports = {src_port, dst_port}
    if 53 in ports:
        return "DNS"
    if 80 in ports or 8080 in ports or 8000 in ports:
        return "HTTP"
    if 443 in ports or 8443 in ports:
        return "TLS"
    if 123 in ports:
        return "NTP"
    if 22 in ports:
        return "SSH"
    return l4_proto


def _endpoint(ip: str, port: int) -> str:
    if ":" in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def _network_packet(frame: bytes, linktype: int):
    if linktype != dpkt.pcap.DLT_EN10MB:
        raise PcapReplayError(
            f"Unsupported link type {linktype}; replay currently requires Ethernet captures."
        )
    ethernet = dpkt.ethernet.Ethernet(frame)
    packet = ethernet.data
    if isinstance(packet, dpkt.ip.IP):
        return packet
    if isinstance(packet, dpkt.ip6.IP6):
        return packet
    return None


def _transport(packet):
    if isinstance(packet, dpkt.ip.IP):
        src = socket.inet_ntop(socket.AF_INET, packet.src)
        dst = socket.inet_ntop(socket.AF_INET, packet.dst)
    else:
        src = socket.inet_ntop(socket.AF_INET6, packet.src)
        dst = socket.inet_ntop(socket.AF_INET6, packet.dst)

    transport = packet.data
    if isinstance(transport, dpkt.tcp.TCP):
        return src, dst, "TCP", transport.sport, transport.dport, bytes(transport.data)
    if isinstance(transport, dpkt.udp.UDP):
        return src, dst, "UDP", transport.sport, transport.dport, bytes(transport.data)
    if isinstance(transport, dpkt.icmp.ICMP) or isinstance(transport, dpkt.icmp6.ICMP6):
        payload = transport.data
        payload = getattr(payload, "data", payload)
        return src, dst, "ICMP", 0, 0, bytes(payload) if isinstance(payload, bytes) else b""
    return src, dst, None, 0, 0, b""


def _add_application_metadata(flow: _Flow, payload: bytes) -> None:
    if flow.l4_proto == "UDP" and (flow.src_port == 53 or flow.dst_port == 53):
        try:
            message = dpkt.dns.DNS(payload)
            if message.qr == dpkt.dns.DNS_Q and message.qd:
                name = message.qd[0].name.rstrip(".")
                if name:
                    flow.dns_queries.append(name[:2048])
        except (dpkt.NeedData, dpkt.UnpackError, ValueError, struct.error):
            pass

    if flow.l4_proto != "TCP" or not payload or flow.http_url:
        return
    if flow.src_port not in {80, 8080, 8000} and flow.dst_port not in {80, 8080, 8000}:
        return
    try:
        request = dpkt.http.Request(bytes(flow.app_data))
    except (dpkt.NeedData, dpkt.UnpackError, ValueError, struct.error):
        return
    flow.http_host = request.headers.get("host", "")[:255] or None
    flow.http_user_agent = request.headers.get("user-agent", "")[:2048] or None
    flow.http_url = request.uri[:2048] or None


def parse_pcap(data: bytes) -> tuple[list[dict[str, Any]], int]:
    """Parse an Ethernet PCAP/PCAPNG into bounded directional flow records."""
    if not data:
        raise PcapReplayError("The uploaded capture is empty.")

    stream = io.BytesIO(data)
    try:
        if data.startswith(b"\x0a\x0d\x0d\x0a"):
            reader = dpkt.pcapng.Reader(stream)
        else:
            reader = dpkt.pcap.Reader(stream)
        linktype = reader.datalink()
    except (dpkt.NeedData, dpkt.UnpackError, ValueError, EOFError, struct.error) as exc:
        raise PcapReplayError("Invalid or unsupported PCAP/PCAPNG file.") from exc

    if linktype != dpkt.pcap.DLT_EN10MB:
        raise PcapReplayError(
            f"Unsupported link type {linktype}; replay currently requires Ethernet captures."
        )

    flows: dict[tuple[Any, ...], _Flow] = {}
    skipped_packets = 0
    packet_count = 0
    try:
        for timestamp, frame in reader:
            packet_count += 1
            if packet_count > MAX_REPLAY_PACKETS:
                raise PcapReplayError(
                    f"Capture exceeds the {MAX_REPLAY_PACKETS:,}-packet replay limit."
                )
            try:
                network = _network_packet(frame, linktype)
                if network is None:
                    skipped_packets += 1
                    continue
                src, dst, protocol, src_port, dst_port, payload = _transport(network)
                if protocol is None:
                    skipped_packets += 1
                    continue
            except (dpkt.NeedData, dpkt.UnpackError, ValueError, IndexError, struct.error):
                skipped_packets += 1
                continue

            key = (src, src_port, dst, dst_port, protocol)
            flow = flows.get(key)
            if flow is None:
                if len(flows) >= MAX_REPLAY_FLOWS:
                    raise PcapReplayError(
                        f"Capture exceeds the {MAX_REPLAY_FLOWS:,}-flow replay limit."
                    )
                flow = _Flow(
                    src_ip=src,
                    src_port=src_port,
                    dst_ip=dst,
                    dst_port=dst_port,
                    l4_proto=protocol,
                    protocol=_app_protocol(protocol, src_port, dst_port),
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                flows[key] = flow
            flow.add_packet(timestamp, len(frame), payload)
            _add_application_metadata(flow, payload)
    except PcapReplayError:
        raise
    except (dpkt.NeedData, dpkt.UnpackError, ValueError, EOFError, struct.error) as exc:
        raise PcapReplayError("The capture ended unexpectedly or is malformed.") from exc

    if not flows:
        raise PcapReplayError("No supported IP flows were found in the capture.")

    records = [flow.as_ingest_record(index) for index, flow in enumerate(flows.values(), start=1)]
    return records, skipped_packets
