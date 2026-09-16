import os
import sys
import unittest
import struct

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils import format_mac_address, format_ip_address, format_hex_dump, check_privileges
from packet_parser import ParsedPacket, parse_raw_ethernet_frame, IP_PROTOCOLS, ETHER_TYPES
from scapy_sniffer import scapy_packet_to_parsed, SCAPY_AVAILABLE
from sniffer import TrafficStatistics


class TestPacketSnifferUtils(unittest.TestCase):

    def test_mac_formatting(self):
        raw_mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        formatted = format_mac_address(raw_mac)
        self.assertEqual(formatted, "00:11:22:33:44:55")

    def test_ip_formatting(self):
        raw_ip = bytes([192, 168, 1, 100])
        formatted = format_ip_address(raw_ip)
        self.assertEqual(formatted, "192.168.1.100")

    def test_hex_dump_formatting(self):
        data = b"Hello Network Packet Sniffer!"
        dump = format_hex_dump(data)
        self.assertIn("Hello Network Pa", dump)
        self.assertIn("48 65 6c 6c 6f", dump)  # "Hello" in hex

    def test_check_privileges(self):
        has_priv, msg = check_privileges()
        self.assertIsInstance(has_priv, bool)
        self.assertIsInstance(msg, str)


class TestPacketParser(unittest.TestCase):

    def test_parsed_packet_model(self):
        pkt = ParsedPacket(packet_id=42)
        pkt.src_ip = "10.0.0.1"
        pkt.dst_ip = "10.0.0.2"
        pkt.src_port = 12345
        pkt.dst_port = 80
        pkt.ip_protocol_name = "TCP"
        pkt.app_protocol = "HTTP"
        pkt.payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"

        summary = pkt.summary()
        self.assertIn("10.0.0.1:12345 -> 10.0.0.2:80", summary)
        self.assertIn("HTTP", summary)

        detailed = pkt.detailed()
        self.assertIn("Layer 2: Ethernet Frame", detailed)
        self.assertIn("Layer 3: IP", detailed)
        self.assertIn("Layer 4: TCP Segment", detailed)
        self.assertIn("GET /index.html", detailed)

        dict_out = pkt.to_dict()
        self.assertEqual(dict_out["id"], 42)
        self.assertEqual(dict_out["network"]["src_ip"], "10.0.0.1")
        self.assertEqual(dict_out["transport"]["dst_port"], 80)

    def test_parse_raw_ethernet_ipv4_tcp(self):
        # Construct synthetic L2 Ethernet + L3 IPv4 + L4 TCP frame
        dst_mac = bytes([0x00, 0x0c, 0x29, 0x11, 0x22, 0x33])
        src_mac = bytes([0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc])
        eth_type = struct.pack('!H', 0x0800)  # IPv4
        eth_hdr = dst_mac + src_mac + eth_type

        # IPv4 Header (20 bytes)
        # Version 4, IHL 5 -> 0x45, TOS 0, Total Len 40, ID 1, Flags 0, TTL 64, Proto 6 (TCP), Checksum 0, Src 192.168.1.5, Dst 192.168.1.1
        src_ip = bytes([192, 168, 1, 5])
        dst_ip = bytes([192, 168, 1, 1])
        ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0, 64, 6, 0, src_ip, dst_ip)

        # TCP Header (20 bytes)
        # Src Port 4433, Dst Port 80, Seq 100, Ack 0, DataOffset 5 (0x50), Flags SYN (0x02), Window 8192, Checksum 0, Urgent 0
        tcp_hdr = struct.pack('!HHIIHHHH', 4433, 80, 100, 0, (5 << 12) | 0x02, 8192, 0, 0)

        raw_frame = eth_hdr + ip_hdr + tcp_hdr + b"TEST_PAYLOAD"

        pkt = parse_raw_ethernet_frame(raw_frame, packet_id=1)
        self.assertEqual(pkt.src_mac, "00:50:56:aa:bb:cc")
        self.assertEqual(pkt.dst_mac, "00:0c:29:11:22:33")
        self.assertEqual(pkt.src_ip, "192.168.1.5")
        self.assertEqual(pkt.dst_ip, "192.168.1.1")
        self.assertEqual(pkt.ip_protocol_name, "TCP")
        self.assertEqual(pkt.src_port, 4433)
        self.assertEqual(pkt.dst_port, 80)
        self.assertTrue(pkt.tcp_flags.get("SYN"))
        self.assertEqual(pkt.payload, b"TEST_PAYLOAD")

    def test_parse_raw_ethernet_arp(self):
        dst_mac = bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
        src_mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        eth_type = struct.pack('!H', 0x0806)  # ARP
        eth_hdr = dst_mac + src_mac + eth_type

        # ARP Request (28 bytes)
        # Hardware: Eth (1), Protocol: IP (0x0800), HW Len 6, Proto Len 4, Op 1 (Req)
        sha = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        spa = bytes([192, 168, 1, 10])
        tha = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        tpa = bytes([192, 168, 1, 1])
        arp_hdr = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, sha, spa, tha, tpa)

        raw_frame = eth_hdr + arp_hdr
        pkt = parse_raw_ethernet_frame(raw_frame, packet_id=2)

        self.assertEqual(pkt.eth_proto, "ARP")
        self.assertEqual(pkt.arp_op, "Request")
        self.assertEqual(pkt.arp_sender_ip, "192.168.1.10")
        self.assertEqual(pkt.arp_target_ip, "192.168.1.1")


class TestStatistics(unittest.TestCase):

    def test_traffic_statistics(self):
        stats = TrafficStatistics()
        
        p1 = ParsedPacket(1)
        p1.ip_protocol_name = "TCP"
        p1.src_ip = "192.168.1.2"
        p1.dst_ip = "8.8.8.8"
        p1.dst_port = 53
        p1.total_length = 100

        p2 = ParsedPacket(2)
        p2.ip_protocol_name = "UDP"
        p2.src_ip = "192.168.1.2"
        p2.dst_ip = "8.8.8.8"
        p2.dst_port = 53
        p2.total_length = 200

        stats.update(p1)
        stats.update(p2)

        self.assertEqual(stats.total_packets, 2)
        self.assertEqual(stats.total_bytes, 300)
        self.assertEqual(stats.protocols["TCP"], 1)
        self.assertEqual(stats.protocols["UDP"], 1)
        self.assertEqual(stats.src_ips["192.168.1.2"], 2)


if __name__ == "__main__":
    unittest.main()
