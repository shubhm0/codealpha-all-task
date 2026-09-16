import os
import sys
import ctypes
import platform
from typing import List, Tuple, Optional

# Color formatting helper for terminal UI
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    DIM = '\033[2m'

    @classmethod
    def disable(cls):
        cls.HEADER = ''
        cls.BLUE = ''
        cls.CYAN = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.RED = ''
        cls.BOLD = ''
        cls.UNDERLINE = ''
        cls.RESET = ''
        cls.DIM = ''

# Enable colorama support on Windows CMD if available
try:
    import colorama
    colorama.init()
except ImportError:
    pass


def check_privileges() -> Tuple[bool, str]:
    """
    Check if current process has privileges required for raw packet sniffing.
    Returns (has_admin, message).
    """
    system_os = platform.system()
    if system_os == "Windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                return True, "Running with Administrator privileges."
            else:
                return False, "Administrator rights required for live raw packet capture on Windows. (Tip: Open PowerShell/CMD as Administrator)."
        except Exception:
            return False, "Unable to verify Windows Administrator status."
    else:
        # Linux / macOS check
        is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
        if is_root:
            return True, "Running as root user."
        else:
            return False, "Root/sudo privileges required for packet capture on Unix/Linux systems."


def get_available_interfaces() -> List[str]:
    """
    Retrieve list of available network interfaces using Scapy or socket fallback.
    """
    interfaces = []
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
    except Exception:
        pass

    if not interfaces:
        try:
            import socket
            hostname = socket.gethostname()
            interfaces = [socket.gethostbyname(hostname)]
        except Exception:
            interfaces = ["Default Interface"]

    return interfaces


def format_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Format raw binary payload bytes into classic Wireshark/hexdump format.
    Example:
    0000   45 00 00 3c 1c 46 40 00  40 06 b1 e6 c0 a8 01 01   E..<... @.......
    """
    if not data:
        return "  <Empty Payload>"

    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        
        # Hex representation
        hex_bytes = []
        for j, byte in enumerate(chunk):
            hex_bytes.append(f"{byte:02x}")
            if j == 7:  # Extra space after 8 bytes
                hex_bytes.append("")
        
        hex_str = " ".join(hex_bytes).ljust(bytes_per_line * 3 + 1)
        
        # ASCII representation (printable characters only)
        ascii_chars = "".join([chr(b) if 32 <= b <= 126 else "." for b in chunk])
        
        lines.append(f"  {i:04x}   {hex_str}   {ascii_chars}")
        
    return "\n".join(lines)


def format_mac_address(raw_mac: bytes) -> str:
    """
    Convert 6 raw bytes into standard MAC address string (e.g. AA:BB:CC:DD:EE:FF).
    """
    if not raw_mac or len(raw_mac) != 6:
        return "00:00:00:00:00:00"
    return ":".join(f"{b:02x}" for b in raw_mac)


def format_ip_address(raw_ip: bytes) -> str:
    """
    Convert 4 raw bytes into dotted-decimal IPv4 address string (e.g. 192.168.1.1).
    """
    if not raw_ip or len(raw_ip) != 4:
        return "0.0.0.0"
    return ".".join(str(b) for b in raw_ip)
