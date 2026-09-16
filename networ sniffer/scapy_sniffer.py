import time
import os
import sys
import warnings
import logging
from typing import Callable, List, Optional
from packet_parser import ParsedPacket, parse_raw_ethernet_frame, WELL_KNOWN_PORTS

# Suppress Scapy deprecation and provider warnings
warnings.filterwarnings("ignore")
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    # Temporarily redirect stderr during Scapy load to silence optional libpcap warning
    _orig_stderr = sys.stderr
    sys.stderr = open(os.devnull, 'w')
    import scapy.all as scapy
    sys.stderr.close()
    sys.stderr = _orig_stderr
    SCAPY_AVAILABLE = True
except Exception:
    sys.stderr = _orig_stderr
    SCAPY_AVAILABLE = False
    scapy = None


def scapy_packet_to_parsed(packet, packet_id: int = 1) -> ParsedPacket:
    """
    Convert a native Scapy packet object into our unified ParsedPacket model.
    """
    pkt = ParsedPacket(packet_id=packet_id, timestamp=float(packet.time) if hasattr(packet, 'time') else None)
    pkt.total_length = len(packet)

    # Layer 2 Ethernet
    if packet.haslayer(scapy.Ether):
        pkt.src_mac = packet[scapy.Ether].src
        pkt.dst_mac = packet[scapy.Ether].dst
        eth_type = packet[scapy.Ether].type
        if eth_type == 0x0800:
            pkt.eth_proto = "IPv4"
        elif eth_type == 0x0806:
            pkt.eth_proto = "ARP"
        elif eth_type == 0x86DD:
            pkt.eth_proto = "IPv6"
        else:
            pkt.eth_proto = f"0x{eth_type:04x}"

    # ARP Layer
    if packet.haslayer(scapy.ARP):
        arp = packet[scapy.ARP]
        pkt.ip_protocol_name = "ARP"
        pkt.eth_proto = "ARP"
        pkt.arp_op = "Request" if arp.op == 1 else "Reply" if arp.op == 2 else str(arp.op)
        pkt.arp_sender_mac = arp.hwsrc
        pkt.arp_sender_ip = arp.psrc
        pkt.arp_target_mac = arp.hwdst
        pkt.arp_target_ip = arp.pdst
        pkt.src_ip = arp.psrc
        pkt.dst_ip = arp.pdst
        return pkt

    # Layer 3 IPv4
    if packet.haslayer(scapy.IP):
        ip = packet[scapy.IP]
        pkt.version = ip.version
        pkt.src_ip = ip.src
        pkt.dst_ip = ip.dst
        pkt.ttl = ip.ttl
        pkt.ip_protocol_id = ip.proto
        pkt.ip_header_len = ip.ihl * 4 if hasattr(ip, 'ihl') else 20
        pkt.total_length = ip.len if hasattr(ip, 'len') else len(packet)

        # Layer 4 TCP
        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            pkt.ip_protocol_name = "TCP"
            pkt.src_port = tcp.sport
            pkt.dst_port = tcp.dport
            pkt.seq_num = tcp.seq
            pkt.ack_num = tcp.ack
            pkt.window_size = tcp.window
            
            # TCP Flags
            flags = str(tcp.flags)
            pkt.tcp_flags = {
                "FIN": "F" in flags,
                "SYN": "S" in flags,
                "RST": "R" in flags,
                "PSH": "P" in flags,
                "ACK": "A" in flags,
                "URG": "U" in flags
            }
            if hasattr(tcp, 'payload') and tcp.payload:
                pkt.payload = bytes(tcp.payload)

        # Layer 4 UDP
        elif packet.haslayer(scapy.UDP):
            udp = packet[scapy.UDP]
            pkt.ip_protocol_name = "UDP"
            pkt.src_port = udp.sport
            pkt.dst_port = udp.dport
            if hasattr(udp, 'payload') and udp.payload:
                pkt.payload = bytes(udp.payload)

        # Layer 4 ICMP
        elif packet.haslayer(scapy.ICMP):
            icmp = packet[scapy.ICMP]
            pkt.ip_protocol_name = "ICMP"
            pkt.icmp_type = icmp.type
            pkt.icmp_code = icmp.code
            if hasattr(icmp, 'payload') and icmp.payload:
                pkt.payload = bytes(icmp.payload)
        else:
            pkt.ip_protocol_name = f"Proto({ip.proto})"
            if hasattr(ip, 'payload') and ip.payload:
                pkt.payload = bytes(ip.payload)

    # Layer 3 IPv6
    elif packet.haslayer(scapy.IPv6):
        ip6 = packet[scapy.IPv6]
        pkt.version = 6
        pkt.src_ip = ip6.src
        pkt.dst_ip = ip6.dst
        pkt.ip_protocol_name = "IPv6"
        if hasattr(ip6, 'payload') and ip6.payload:
            pkt.payload = bytes(ip6.payload)

    # Application protocol identification
    if pkt.src_port in WELL_KNOWN_PORTS:
        pkt.app_protocol = WELL_KNOWN_PORTS[pkt.src_port]
    elif pkt.dst_port in WELL_KNOWN_PORTS:
        pkt.app_protocol = WELL_KNOWN_PORTS[pkt.dst_port]

    if pkt.payload:
        if pkt.payload.startswith((b'GET ', b'POST ', b'HTTP/', b'HEAD ', b'PUT ', b'DELETE ')):
            pkt.app_protocol = "HTTP"
        elif len(pkt.payload) > 5 and pkt.payload[0] == 0x16:
            pkt.app_protocol = "TLS/SSL"

    return pkt


class ScapySnifferEngine:
    """
    Capture engine utilizing Scapy library for live packet sniffing and PCAP operations.
    """

    def __init__(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy library is not installed. Run 'pip install scapy' to install it.")
        
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = 0
        self.captured_scapy_packets = []

    def start_sniffing(
        self,
        count: int = 0,
        callback: Optional[Callable[[ParsedPacket], None]] = None,
        store: bool = True
    ) -> List[ParsedPacket]:
        """
        Start live packet capture.
        - count: 0 for continuous sniffing until Ctrl+C.
        - callback: Function invoked on each captured packet.
        - store: Whether to store raw packets in memory for PCAP saving.
        """
        parsed_packets = []
        self.packet_count = 0

        def _internal_callback(packet):
            self.packet_count += 1
            if store:
                self.captured_scapy_packets.append(packet)

            parsed_pkt = scapy_packet_to_parsed(packet, packet_id=self.packet_count)
            parsed_packets.append(parsed_pkt)

            if callback:
                callback(parsed_pkt)

        kwargs = {
            "prn": _internal_callback,
            "store": False
        }

        if count > 0:
            kwargs["count"] = count
        if self.interface and self.interface.lower() != "auto":
            kwargs["iface"] = self.interface
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter

        try:
            scapy.sniff(**kwargs)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            if "winpcap" in str(e).lower() or "layer 2" in str(e).lower():
                print(f"[!] Scapy Layer 2 capture unavailable without WinPcap/Npcap driver. Switching to Layer 3 Socket mode...")
                try:
                    scapy.conf.L3socket = scapy.L3RawSocket
                    scapy.sniff(**kwargs)
                except Exception as l3_err:
                    print(f"[!] Layer 3 socket fallback failed: {l3_err}")
                    raise e
            else:
                raise e

        return parsed_packets

    def save_pcap(self, filepath: str):
        """
        Save captured packets to a PCAP file.
        """
        if not self.captured_scapy_packets:
            raise ValueError("No packets available to save to PCAP file.")
        scapy.wrpcap(filepath, self.captured_scapy_packets)

    @staticmethod
    def read_pcap(filepath: str) -> List[ParsedPacket]:
        """
        Read packets from an existing PCAP file.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy library is required to read PCAP files.")
        
        scapy_packets = scapy.rdpcap(filepath)
        parsed_list = []
        for idx, pkt in enumerate(scapy_packets, start=1):
            parsed_list.append(scapy_packet_to_parsed(pkt, packet_id=idx))
        return parsed_list
