import io
import socket
import unittest

import dpkt

from app.pcap_replay import PcapReplayError, parse_pcap


def _tcp_frame(src_ip, dst_ip, src_port, dst_port, payload, ipv6=False):
    tcp = dpkt.tcp.TCP(
        sport=src_port,
        dport=dst_port,
        seq=1,
        flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
        data=payload,
    )
    if ipv6:
        ip = dpkt.ip6.IP6(
            src=socket.inet_pton(socket.AF_INET6, src_ip),
            dst=socket.inet_pton(socket.AF_INET6, dst_ip),
            nxt=dpkt.ip.IP_PROTO_TCP,
            hlim=64,
            data=tcp,
        )
        eth_type = dpkt.ethernet.ETH_TYPE_IP6
    else:
        ip = dpkt.ip.IP(
            src=socket.inet_aton(src_ip),
            dst=socket.inet_aton(dst_ip),
            p=dpkt.ip.IP_PROTO_TCP,
            ttl=64,
            data=tcp,
        )
        eth_type = dpkt.ethernet.ETH_TYPE_IP
    return bytes(dpkt.ethernet.Ethernet(type=eth_type, data=ip))


def _capture(packets, pcapng=False):
    stream = io.BytesIO()
    writer = dpkt.pcapng.Writer(stream) if pcapng else dpkt.pcap.Writer(stream)
    for timestamp, packet in packets:
        writer.writepkt(packet, ts=timestamp)
    return stream.getvalue()


class PcapReplayTests(unittest.TestCase):
    def test_reconstructs_directional_http_flow_and_metadata(self):
        request = (
            b"GET /search?q=covert HTTP/1.1\r\n"
            b"Host: example.test\r\nUser-Agent: replay-test\r\n\r\n"
        )
        capture = _capture([
            (1.0, _tcp_frame("192.0.2.10", "198.51.100.20", 41000, 80, request)),
            (1.25, _tcp_frame("192.0.2.10", "198.51.100.20", 41000, 80, b"payload")),
        ])

        records, skipped = parse_pcap(capture)

        self.assertEqual(skipped, 0)
        self.assertEqual(len(records), 1)
        flow = records[0]
        self.assertEqual(flow["src"], "192.0.2.10:41000")
        self.assertEqual(flow["protocol"], "HTTP")
        self.assertEqual(flow["packets"], 2)
        self.assertEqual(flow["duration_ms"], 250)
        self.assertEqual(flow["http_host"], "example.test")
        self.assertEqual(flow["http_user_agent"], "replay-test")
        self.assertEqual(flow["http_url"], "/search?q=covert")

    def test_formats_ipv6_endpoints_for_database_ingestion(self):
        capture = _capture([
            (1.0, _tcp_frame("2001:db8::1", "2001:db8::2", 41000, 22, b"ssh", ipv6=True)),
        ])

        records, _ = parse_pcap(capture)

        self.assertEqual(records[0]["src"], "[2001:db8::1]:41000")
        self.assertEqual(records[0]["dst"], "[2001:db8::2]:22")
        self.assertEqual(records[0]["protocol"], "SSH")

    def test_accepts_ethernet_pcapng(self):
        capture = _capture([
            (1.0, _tcp_frame("192.0.2.1", "198.51.100.1", 50000, 443, b"tls")),
        ], pcapng=True)

        records, skipped = parse_pcap(capture)

        self.assertEqual(skipped, 0)
        self.assertEqual(records[0]["protocol"], "TLS")

    def test_rejects_invalid_capture(self):
        with self.assertRaises(PcapReplayError):
            parse_pcap(b"not a pcap")


if __name__ == "__main__":
    unittest.main()
