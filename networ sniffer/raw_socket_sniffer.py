import socket
import platform
import select
from typing import Callable, List, Optional
from packet_parser import ParsedPacket, parse_raw_ethernet_frame, _parse_ipv4_bytes

class RawSocketSnifferEngine:
    """
    Educational raw socket sniffer using Python standard library `socket` module.
    - Demonstrates direct OS socket interface interaction and binary struct unpacking.
    """

    def __init__(self, host_ip: str = "0.0.0.0"):
        self.host_ip = host_ip
        self.system_os = platform.system()
        self.sock: Optional[socket.socket] = None
        self.packet_count = 0

    def _create_socket(self) -> socket.socket:
        """
        Create raw socket appropriate for host OS.
        """
        if self.system_os == "Linux":
            # ETH_P_ALL = 0x0003 (capture all Ethernet frames L2)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            return sock
        elif self.system_os == "Windows":
            # Windows Raw IP Socket (L3)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((self.host_ip, 0))
            # Enable Promiscuous / Receive All mode on Windows
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except Exception as e:
                print(f"[Warning] SIO_RCVALL promiscuous mode failed: {e}")
            return sock
        else:
            # macOS / BSD fallback
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            return sock

    def start_sniffing(
        self,
        count: int = 0,
        callback: Optional[Callable[[ParsedPacket], None]] = None
    ) -> List[ParsedPacket]:
        """
        Start sniffing network traffic using raw sockets.
        """
        parsed_packets = []
        self.packet_count = 0
        self.sock = self._create_socket()

        try:
            while True:
                if count > 0 and self.packet_count >= count:
                    break

                # Non-blocking wait for packet ready with timeout so Ctrl+C responds cleanly
                r, _, _ = select.select([self.sock], [], [], 0.5)
                if not r:
                    continue

                raw_bytes, addr = self.sock.recvfrom(65535)
                self.packet_count += 1

                if self.system_os == "Linux":
                    # Linux receives L2 Ethernet frame
                    parsed_pkt = parse_raw_ethernet_frame(raw_bytes, packet_id=self.packet_count)
                else:
                    # Windows / BSD receives L3 IP packet
                    parsed_pkt = ParsedPacket(packet_id=self.packet_count)
                    parsed_pkt.src_ip = addr[0] if isinstance(addr, tuple) and addr else "0.0.0.0"
                    _parse_ipv4_bytes(raw_bytes, parsed_pkt)

                parsed_packets.append(parsed_pkt)

                if callback:
                    callback(parsed_pkt)

        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

        return parsed_packets

    def stop(self):
        """
        Clean up socket and disable promiscuous mode.
        """
        if self.sock:
            if self.system_os == "Windows":
                try:
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
