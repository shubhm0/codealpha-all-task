import struct
import datetime
from typing import Dict, Any, Optional, List
from utils import Colors, format_hex_dump, format_mac_address, format_ip_address

# Protocol Mappings
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF"
}

ETHER_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN"
}

WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}


class ParsedPacket:
    """
    Data structure representing a fully parsed network packet.
    """

    def __init__(self, packet_id: int = 1, timestamp: Optional[float] = None):
        self.packet_id = packet_id
        self.timestamp = timestamp or datetime.datetime.now().timestamp()
        
        # Layer 2 (Data Link)
        self.src_mac: str = "00:00:00:00:00:00"
        self.dst_mac: str = "00:00:00:00:00:00"
        self.eth_proto: str = "IPv4"
        
        # Layer 3 (Network)
        self.version: int = 4
        self.src_ip: str = "0.0.0.0"
        self.dst_ip: str = "0.0.0.0"
        self.ip_protocol_id: int = 6
        self.ip_protocol_name: str = "TCP"
        self.ttl: int = 64
        self.ip_header_len: int = 20
        self.total_length: int = 0
        
        # Layer 4 (Transport)
        self.src_port: Optional[int] = None
        self.dst_port: Optional[int] = None
        self.tcp_flags: Dict[str, bool] = {}
        self.seq_num: Optional[int] = None
        self.ack_num: Optional[int] = None
        self.window_size: Optional[int] = None
        self.icmp_type: Optional[int] = None
        self.icmp_code: Optional[int] = None
        
        # ARP specific
        self.arp_op: Optional[str] = None
        self.arp_sender_mac: Optional[str] = None
        self.arp_sender_ip: Optional[str] = None
        self.arp_target_mac: Optional[str] = None
        self.arp_target_ip: Optional[str] = None

        # Layer 7 (Application / Payload)
        self.app_protocol: str = "Unknown"
        self.payload: bytes = b""
        self.payload_preview: str = ""

    @property
    def formatted_time(self) -> str:
        dt = datetime.datetime.fromtimestamp(self.timestamp)
        return dt.strftime("%H:%M:%S.%f")[:-3]

    def summary(self) -> str:
        """
        Single line summary output.
        """
        color = Colors.GREEN
        if self.ip_protocol_name == "TCP":
            color = Colors.CYAN
        elif self.ip_protocol_name == "UDP":
            color = Colors.YELLOW
        elif self.ip_protocol_name == "ICMP":
            color = Colors.RED
        elif self.eth_proto == "ARP":
            color = Colors.HEADER

        if self.eth_proto == "ARP":
            info = f"ARP {self.arp_op}: {self.arp_sender_ip} ({self.arp_sender_mac}) -> {self.arp_target_ip}"
        elif self.src_port and self.dst_port:
            flags_str = ""
            if self.tcp_flags:
                active_flags = [k for k, v in self.tcp_flags.items() if v]
                if active_flags:
                    flags_str = f" [{','.join(active_flags)}]"

            app_label = f" ({self.app_protocol})" if self.app_protocol != "Unknown" else ""
            info = f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}{app_label}{flags_str}"
        else:
            info = f"{self.src_ip} -> {self.dst_ip}"

        return (
            f"{Colors.DIM}#{self.packet_id:04d}{Colors.RESET} | "
            f"{self.formatted_time} | "
            f"{color}{self.ip_protocol_name:<5}{Colors.RESET} | "
            f"Len={self.total_length:<4} | "
            f"{info}"
        )

    def detailed(self) -> str:
        """
        Multi-line detailed packet view showing all layers.
        """
        lines = []
        lines.append(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        lines.append(f"{Colors.BOLD}PACKET #{self.packet_id} - Captured at {self.formatted_time}{Colors.RESET}")
        lines.append(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        
        # Layer 2
        lines.append(f"{Colors.BLUE}[Layer 2: Ethernet Frame]{Colors.RESET}")
        lines.append(f"  Source MAC     : {self.src_mac}")
        lines.append(f"  Destination MAC: {self.dst_mac}")
        lines.append(f"  EtherType      : {self.eth_proto}")

        # ARP Layer
        if self.eth_proto == "ARP":
            lines.append(f"{Colors.HEADER}[Layer 3: ARP - Address Resolution Protocol]{Colors.RESET}")
            lines.append(f"  Operation      : {self.arp_op}")
            lines.append(f"  Sender MAC     : {self.arp_sender_mac}")
            lines.append(f"  Sender IP      : {self.arp_sender_ip}")
            lines.append(f"  Target MAC     : {self.arp_target_mac}")
            lines.append(f"  Target IP      : {self.arp_target_ip}")
            lines.append(f"{Colors.BOLD}{'-' * 70}{Colors.RESET}")
            return "\n".join(lines)

        # Layer 3
        lines.append(f"{Colors.GREEN}[Layer 3: IP (v{self.version})]{Colors.RESET}")
        lines.append(f"  Source IP      : {self.src_ip}")
        lines.append(f"  Destination IP : {self.dst_ip}")
        lines.append(f"  Protocol       : {self.ip_protocol_name} ({self.ip_protocol_id})")
        lines.append(f"  TTL            : {self.ttl}")
        lines.append(f"  Header Length  : {self.ip_header_len} bytes")
        lines.append(f"  Total Length   : {self.total_length} bytes")

        # Layer 4
        if self.ip_protocol_name == "TCP":
            lines.append(f"{Colors.CYAN}[Layer 4: TCP Segment]{Colors.RESET}")
            lines.append(f"  Source Port    : {self.src_port}")
            lines.append(f"  Destination Port: {self.dst_port}")
            lines.append(f"  Seq Number     : {self.seq_num}")
            lines.append(f"  Ack Number     : {self.ack_num}")
            lines.append(f"  Window Size    : {self.window_size}")
            if self.tcp_flags:
                active_flags = [k for k, v in self.tcp_flags.items() if v]
                lines.append(f"  Flags          : {', '.join(active_flags)}")

        elif self.ip_protocol_name == "UDP":
            lines.append(f"{Colors.YELLOW}[Layer 4: UDP Datagram]{Colors.RESET}")
            lines.append(f"  Source Port    : {self.src_port}")
            lines.append(f"  Destination Port: {self.dst_port}")

        elif self.ip_protocol_name == "ICMP":
            lines.append(f"{Colors.RED}[Layer 4: ICMP Control Message]{Colors.RESET}")
            lines.append(f"  Type           : {self.icmp_type}")
            lines.append(f"  Code           : {self.icmp_code}")

        # Layer 7 & Payload
        if self.app_protocol != "Unknown":
            lines.append(f"{Colors.HEADER}[Layer 7: Application Protocol - {self.app_protocol}]{Colors.RESET}")

        lines.append(f"{Colors.DIM}[Payload Data ({len(self.payload)} bytes)]{Colors.RESET}")
        lines.append(format_hex_dump(self.payload))
        lines.append(f"{Colors.BOLD}{'-' * 70}{Colors.RESET}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert packet data to JSON-serializable dictionary.
        """
        return {
            "id": self.packet_id,
            "timestamp": self.timestamp,
            "formatted_time": self.formatted_time,
            "ethernet": {
                "src_mac": self.src_mac,
                "dst_mac": self.dst_mac,
                "proto": self.eth_proto
            },
            "network": {
                "version": self.version,
                "src_ip": self.src_ip,
                "dst_ip": self.dst_ip,
                "protocol": self.ip_protocol_name,
                "ttl": self.ttl,
                "length": self.total_length
            },
            "transport": {
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "flags": self.tcp_flags,
                "seq_num": self.seq_num,
                "ack_num": self.ack_num,
                "icmp_type": self.icmp_type,
                "icmp_code": self.icmp_code
            },
            "application": self.app_protocol,
            "payload_size": len(self.payload)
        }


def parse_raw_ethernet_frame(raw_data: bytes, packet_id: int = 1) -> ParsedPacket:
    """
    Parse a raw L2 Ethernet frame bytes into a structured ParsedPacket object.
    Ethernet Header format:
    Destination MAC (6 bytes) | Source MAC (6 bytes) | EtherType (2 bytes) | Payload ...
    """
    pkt = ParsedPacket(packet_id=packet_id)
    pkt.total_length = len(raw_data)

    if len(raw_data) < 14:
        pkt.payload = raw_data
        return pkt

    dst_mac_bytes, src_mac_bytes, eth_type_num = struct.unpack('!6s6sH', raw_data[:14])
    pkt.dst_mac = format_mac_address(dst_mac_bytes)
    pkt.src_mac = format_mac_address(src_mac_bytes)
    pkt.eth_proto = ETHER_TYPES.get(eth_type_num, f"0x{eth_type_num:04x}")

    l3_data = raw_data[14:]

    # Parse ARP frame
    if eth_type_num == 0x0806:
        pkt.ip_protocol_name = "ARP"
        if len(l3_data) >= 28:
            hrd, pro, hln, pln, op, sha, spa, tha, tpa = struct.unpack('!HHBBH6s4s6s4s', l3_data[:28])
            pkt.arp_op = "Request" if op == 1 else "Reply" if op == 2 else f"Opcode({op})"
            pkt.arp_sender_mac = format_mac_address(sha)
            pkt.arp_sender_ip = format_ip_address(spa)
            pkt.arp_target_mac = format_mac_address(tha)
            pkt.arp_target_ip = format_ip_address(tpa)
            pkt.src_ip = pkt.arp_sender_ip
            pkt.dst_ip = pkt.arp_target_ip
            pkt.payload = l3_data[28:]
        return pkt

    # Parse IPv4 packet
    if eth_type_num == 0x0800 or (len(raw_data) >= 20 and (raw_data[0] >> 4) == 4):
        _parse_ipv4_bytes(l3_data, pkt)

    return pkt


def _parse_ipv4_bytes(ip_data: bytes, pkt: ParsedPacket):
    """
    Parse standard IPv4 raw header bytes into ParsedPacket.
    Header format:
    Version/IHL (1B) | DSCP/ECN (1B) | Length (2B) | Identification (2B) |
    Flags/Offset (2B) | TTL (1B) | Protocol (1B) | Checksum (2B) | Source IP (4B) | Dest IP (4B)
    """
    if len(ip_data) < 20:
        pkt.payload = ip_data
        return

    ver_ihl, tos, total_len, pkt_id, flags_offset, ttl, proto_id, checksum, src_ip_b, dst_ip_b = struct.unpack(
        '!BBHHHBBH4s4s', ip_data[:20]
    )

    pkt.version = (ver_ihl >> 4)
    ihl = (ver_ihl & 0x0F)
    pkt.ip_header_len = ihl * 4
    pkt.total_length = total_len or len(ip_data)
    pkt.ttl = ttl
    pkt.ip_protocol_id = proto_id
    pkt.ip_protocol_name = IP_PROTOCOLS.get(proto_id, f"Proto({proto_id})")
    pkt.src_ip = format_ip_address(src_ip_b)
    pkt.dst_ip = format_ip_address(dst_ip_b)

    l4_data = ip_data[pkt.ip_header_len:]

    # Parse TCP Header
    if proto_id == 6 and len(l4_data) >= 20:
        src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack('!HHIIHHHH', l4_data[:20])
        pkt.src_port = src_port
        pkt.dst_port = dst_port
        pkt.seq_num = seq
        pkt.ack_num = ack
        pkt.window_size = window
        
        # Flags extraction
        flags_bits = offset_reserved_flags & 0x01FF
        pkt.tcp_flags = {
            "FIN": bool(flags_bits & 0x001),
            "SYN": bool(flags_bits & 0x002),
            "RST": bool(flags_bits & 0x004),
            "PSH": bool(flags_bits & 0x008),
            "ACK": bool(flags_bits & 0x010),
            "URG": bool(flags_bits & 0x020)
        }

        tcp_header_len = ((offset_reserved_flags >> 12) & 0x0F) * 4
        pkt.payload = l4_data[tcp_header_len:]
        _identify_app_protocol(pkt)

    # Parse UDP Header
    elif proto_id == 17 and len(l4_data) >= 8:
        src_port, dst_port, udp_len, udp_checksum = struct.unpack('!HHHH', l4_data[:8])
        pkt.src_port = src_port
        pkt.dst_port = dst_port
        pkt.payload = l4_data[8:]
        _identify_app_protocol(pkt)

    # Parse ICMP Header
    elif proto_id == 1 and len(l4_data) >= 4:
        icmp_type, icmp_code, icmp_checksum = struct.unpack('!BBH', l4_data[:4])
        pkt.icmp_type = icmp_type
        pkt.icmp_code = icmp_code
        pkt.payload = l4_data[4:]

    else:
        pkt.payload = l4_data


def _identify_app_protocol(pkt: ParsedPacket):
    """
    Detect application layer protocol based on ports or payload signatures.
    """
    if pkt.src_port in WELL_KNOWN_PORTS:
        pkt.app_protocol = WELL_KNOWN_PORTS[pkt.src_port]
    elif pkt.dst_port in WELL_KNOWN_PORTS:
        pkt.app_protocol = WELL_KNOWN_PORTS[pkt.dst_port]

    # Inspect payload signatures
    if pkt.payload:
        if pkt.payload.startswith((b'GET ', b'POST ', b'HTTP/', b'HEAD ', b'PUT ', b'DELETE ')):
            pkt.app_protocol = "HTTP"
        elif len(pkt.payload) > 5 and pkt.payload[0] == 0x22:  # TLS handshake record type 0x16 (22)
            pkt.app_protocol = "TLS/SSL"
