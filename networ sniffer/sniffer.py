#!/usr/bin/env python3
"""
SOCForge Network Packet Sniffer & Protocol Analyzer
=====================================================
A Python tool for live packet capture, deep packet inspection (DPI),
OSI layer analysis, raw payload decoding, and network telemetry export.
"""

import sys
import os
import json
import warnings
import argparse
from typing import List, Dict
from collections import Counter

# Suppress background warnings
warnings.filterwarnings("ignore")

from utils import Colors, check_privileges, get_available_interfaces
from packet_parser import ParsedPacket
from scapy_sniffer import ScapySnifferEngine, SCAPY_AVAILABLE
from raw_socket_sniffer import RawSocketSnifferEngine


def print_banner():
    banner = rf"""
{Colors.CYAN}{Colors.BOLD}========================================================================
   __  _  _ _____ ____ ____ _____   ____ _  _ _ ____ ____ ____ ____ 
   |_| |\ | |___| |__| |--- |___|   [__  |\ | | |--- |--- |___ |--| 
========================================================================{Colors.RESET}
 {Colors.DIM}Network Traffic Packet Sniffer & Deep Protocol Inspection Tool{Colors.RESET}
"""
    print(banner)


class TrafficStatistics:
    """
    Tracks and computes aggregate statistics for captured network traffic.
    """

    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols = Counter()
        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.dst_ports = Counter()

    def update(self, pkt: ParsedPacket):
        self.total_packets += 1
        self.total_bytes += pkt.total_length
        self.protocols[pkt.ip_protocol_name] += 1
        self.src_ips[pkt.src_ip] += 1
        self.dst_ips[pkt.dst_ip] += 1
        if pkt.dst_port:
            self.dst_ports[f"{pkt.dst_port} ({pkt.app_protocol})"] += 1

    def print_summary(self):
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.HEADER}                  CAPTURE STATISTICS & REPORT                         {Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.HEADER}{'=' * 70}{Colors.RESET}")
        print(f" Total Packets Captured : {Colors.BOLD}{self.total_packets}{Colors.RESET}")
        print(f" Total Data Volume      : {Colors.BOLD}{self.total_bytes / 1024:.2f} KB{Colors.RESET} ({self.total_bytes} bytes)")
        
        print(f"\n{Colors.CYAN}[Protocol Distribution]{Colors.RESET}")
        for proto, count in self.protocols.most_common():
            pct = (count / self.total_packets) * 100 if self.total_packets > 0 else 0
            print(f"  - {proto:<10}: {count:>5} packets ({pct:>5.1f}%)")

        print(f"\n{Colors.GREEN}[Top Source IPs]{Colors.RESET}")
        for ip, count in self.src_ips.most_common(5):
            print(f"  - {ip:<18}: {count:>5} packets")

        print(f"\n{Colors.YELLOW}[Top Destination IPs]{Colors.RESET}")
        for ip, count in self.dst_ips.most_common(5):
            print(f"  - {ip:<18}: {count:>5} packets")

        if self.dst_ports:
            print(f"\n{Colors.BLUE}[Top Destination Ports / Services]{Colors.RESET}")
            for port, count in self.dst_ports.most_common(5):
                print(f"  - {port:<22}: {count:>5} packets")

        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Capture, analyze, and decode network traffic packets layer-by-layer."
    )
    parser.add_argument("-i", "--interface", default="auto", help="Network interface to capture on (e.g. eth0, Wi-Fi, auto)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default=None, help="BPF packet filter expression (e.g. 'tcp port 80', 'icmp', 'ip')")
    parser.add_argument("-e", "--engine", choices=["scapy", "socket"], default="scapy", help="Capture engine to use (default: scapy)")
    parser.add_argument("-v", "--verbose", choices=["summary", "detailed", "hex"], default="summary", help="Display verbosity level")
    parser.add_argument("-w", "--write", help="Save captured packets to file (.pcap or .json)")
    parser.add_argument("-r", "--read", help="Read and analyze an existing .pcap file (Offline mode)")
    parser.add_argument("--demo", action="store_true", help="Run simulated network packet capture & analysis demo")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces and exit")

    args = parser.parse_args()

    # List interfaces mode
    if args.list_interfaces:
        print(f"{Colors.BOLD}Available Network Interfaces:{Colors.RESET}")
        ifaces = get_available_interfaces()
        for idx, iface in enumerate(ifaces, 1):
            print(f"  {idx}. {iface}")
        sys.exit(0)

    stats = TrafficStatistics()
    captured_packets: List[ParsedPacket] = []

    # Demo Mode: Generate realistic synthetic network packets for demonstration
    if args.demo:
        print(f"{Colors.GREEN}[+] Running Simulated Packet Capture Demo Mode...{Colors.RESET}\n")
        import time
        from packet_parser import parse_raw_ethernet_frame
        import struct

        # Sample packets: HTTP GET, DNS Query, ICMP Echo, ARP Request, TLS Client Hello
        raw_samples = [
            # 1. IPv4 TCP HTTP GET
            struct.pack('!6s6sH', b'\x00\x0c\x29\x11\x22\x33', b'\x00\x50\x56\xaa\xbb\xcc', 0x0800) +
            struct.pack('!BBHHHBBH4s4s', 0x45, 0, 84, 1, 0, 64, 6, 0, bytes([192,168,1,105]), bytes([93,184,216,34])) +
            struct.pack('!HHIIHHHH', 52344, 80, 1001, 0, (5 << 12) | 0x18, 8192, 0, 0) +
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",

            # 2. IPv4 UDP DNS Query
            struct.pack('!6s6sH', b'\x00\x0c\x29\x11\x22\x33', b'\x00\x50\x56\xaa\xbb\xcc', 0x0800) +
            struct.pack('!BBHHHBBH4s4s', 0x45, 0, 58, 2, 0, 64, 17, 0, bytes([192,168,1,105]), bytes([8,8,8,8])) +
            struct.pack('!HHHH', 61234, 53, 38, 0) +
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",

            # 3. IPv4 ICMP Echo Request
            struct.pack('!6s6sH', b'\x00\x0c\x29\x11\x22\x33', b'\x00\x50\x56\xaa\xbb\xcc', 0x0800) +
            struct.pack('!BBHHHBBH4s4s', 0x45, 0, 60, 3, 0, 128, 1, 0, bytes([192,168,1,105]), bytes([1,1,1,1])) +
            struct.pack('!BBH', 8, 0, 0x4d5c) + b"abcdefghijklmnopqrstuvwabcdefghi",

            # 4. ARP Request
            struct.pack('!6s6sH', b'\xff\xff\xff\xff\xff\xff', b'\x00\x50\x56\xaa\xbb\xcc', 0x0806) +
            struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, b'\x00\x50\x56\xaa\xbb\xcc', bytes([192,168,1,105]), b'\x00\x00\x00\x00\x00\x00', bytes([192,168,1,1])),

            # 5. IPv4 TCP HTTPS / TLS
            struct.pack('!6s6sH', b'\x00\x0c\x29\x11\x22\x33', b'\x00\x50\x56\xaa\xbb\xcc', 0x0800) +
            struct.pack('!BBHHHBBH4s4s', 0x45, 0, 120, 5, 0, 64, 6, 0, bytes([192,168,1,105]), bytes([142,250,190,46])) +
            struct.pack('!HHIIHHHH', 52346, 443, 2001, 500, (5 << 12) | 0x18, 16384, 0, 0) +
            b"\x16\x03\x01\x00\x40\x01\x00\x00\x3c\x03\x03" + b"ClientHello TLSv1.2 Stream Sample Data"
        ]

        target_count = args.count if args.count > 0 else 5
        for i in range(target_count):
            raw_pkt = raw_samples[i % len(raw_samples)]
            parsed = parse_raw_ethernet_frame(raw_pkt, packet_id=i+1)
            stats.update(parsed)
            captured_packets.append(parsed)

            if args.verbose == "detailed" or args.verbose == "hex":
                print(parsed.detailed())
            else:
                print(parsed.summary())
            time.sleep(0.3)

        stats.print_summary()
        sys.exit(0)

    # Offline PCAP playback mode
    if args.read:
        print(f"{Colors.GREEN}[+] Reading PCAP file: {args.read}{Colors.RESET}")
        try:
            captured_packets = ScapySnifferEngine.read_pcap(args.read)
            for pkt in captured_packets:
                stats.update(pkt)
                if args.verbose == "detailed" or args.verbose == "hex":
                    print(pkt.detailed())
                else:
                    print(pkt.summary())
            stats.print_summary()
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to read PCAP file: {e}{Colors.RESET}")
            sys.exit(1)
        sys.exit(0)

    # Privilege Check for live capture
    has_priv, priv_msg = check_privileges()
    if has_priv:
        print(f"{Colors.GREEN}[✓] Privilege Check: {priv_msg}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] Warning: {priv_msg}{Colors.RESET}")

    print(f"{Colors.CYAN}[+] Engine   : {args.engine.upper()}{Colors.RESET}")
    print(f"{Colors.CYAN}[+] Interface: {args.interface}{Colors.RESET}")
    if args.filter:
        print(f"{Colors.CYAN}[+] Filter   : {args.filter}{Colors.RESET}")
    print(f"{Colors.CYAN}[+] Mode     : Verbose ({args.verbose}){Colors.RESET}")
    print(f"{Colors.DIM}Press Ctrl+C at any time to stop capturing and view statistics.{Colors.RESET}\n")

    def _packet_callback(pkt: ParsedPacket):
        stats.update(pkt)
        captured_packets.append(pkt)

        if args.verbose == "detailed" or args.verbose == "hex":
            print(pkt.detailed())
        else:
            print(pkt.summary())

    try:
        if args.engine == "scapy":
            if not SCAPY_AVAILABLE:
                print(f"{Colors.RED}[!] Scapy engine requested but Scapy module not available. Falling back to 'socket' engine.{Colors.RESET}")
                sniffer = RawSocketSnifferEngine()
                sniffer.start_sniffing(count=args.count, callback=_packet_callback)
            else:
                sniffer = ScapySnifferEngine(interface=args.interface, bpf_filter=args.filter)
                sniffer.start_sniffing(count=args.count, callback=_packet_callback, store=bool(args.write and args.write.endswith(".pcap")))
                
                if args.write and args.write.endswith(".pcap"):
                    print(f"\n{Colors.GREEN}[+] Exporting captured packets to PCAP file: {args.write}{Colors.RESET}")
                    sniffer.save_pcap(args.write)

        else:
            sniffer = RawSocketSnifferEngine()
            sniffer.start_sniffing(count=args.count, callback=_packet_callback)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Capture stopped by user.{Colors.RESET}")

    except Exception as e:
        print(f"\n{Colors.RED}[!] Live capture requires Administrator privileges or Npcap driver: {e}{Colors.RESET}")
        print(f"{Colors.CYAN}[Tip] You can run Demo Mode anytime without special privileges using: py sniffer.py --demo{Colors.RESET}\n")

    # Display Statistics Summary
    stats.print_summary()

    # Save to JSON log file if requested
    if args.write and args.write.endswith(".json"):
        try:
            json_data = [pkt.to_dict() for pkt in captured_packets]
            with open(args.write, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2)
            print(f"{Colors.GREEN}[+] Exported {len(json_data)} packet logs to JSON file: {args.write}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to write JSON file: {e}{Colors.RESET}")


if __name__ == "__main__":
    main()
