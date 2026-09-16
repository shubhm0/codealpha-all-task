# Python Network Packet Sniffer & Protocol Analyzer

A feature-rich, educational Python program for real-time network traffic packet capturing, protocol analysis, OSI layer header dissection, binary hexdump payload inspection, and network statistics tracking.

---

## 📚 Educational Guide: How Data Flows Through Networks

### 1. The OSI & TCP/IP Network Models
Network communication relies on standardized layered protocols. When data travels from a source to a destination, it moves through the network stack via **Encapsulation** (on sending) and **Decapsulation** (on receiving).

```
   Sending Host                                           Receiving Host
+-----------------+                                    +-----------------+
|  Application    |  [HTTP / DNS / Payload]            |  Application    |
+-----------------+                                    +-----------------+
        | (Add TCP/UDP Header)                                  ^ (Strip TCP/UDP Header)
        v                                                       |
+-----------------+                                    +-----------------+
|    Transport    |  [TCP/UDP Header | Payload]            |    Transport    |
+-----------------+                                    +-----------------+
        | (Add IP Header)                                       ^ (Strip IP Header)
        v                                                       |
+-----------------+                                    +-----------------+
|     Network     |  [IP Header | Transport | Payload]     |     Network     |
+-----------------+                                    +-----------------+
        | (Add Frame Header & Trailer)                          ^ (Strip Frame Header)
        v                                                       |
+-----------------+                                    +-----------------+
|    Data Link    |  [Ethernet | IP | Transport | Data]   |    Data Link    |
+-----------------+                                    +-----------------+
        | (Raw Bits / Signals over Wire/Wi-Fi)                  |
        +----------------------- Wire --------------------------+
```

---

## 🔍 Protocol Structures Decoded by this Sniffer

### 1. Data Link Layer (Layer 2) — Ethernet Frame
- **Destination MAC (6 bytes)**: Hardware address of destination device/gateway.
- **Source MAC (6 bytes)**: Hardware address of sender.
- **EtherType (2 bytes)**: Identifies the payload protocol (e.g., `0x0800` for IPv4, `0x0806` for ARP, `0x86DD` for IPv6).

### 2. Address Resolution Protocol (ARP)
- Maps Layer 3 IP addresses to Layer 2 MAC addresses on local subnet.
- **Operation**: `1` = Request ("Who has IP 192.168.1.1? Tell 192.168.1.5"), `2` = Reply ("192.168.1.1 is at AA:BB:CC:DD:EE:FF").

### 3. Network Layer (Layer 3) — IPv4 Header
- **Version & IHL**: IPv4 version (4) and header length in 32-bit words (default 20 bytes).
- **Time To Live (TTL)**: Hop count limit preventing routing loops (decremented by each router).
- **Protocol ID**: Identifies L4 protocol (`1` = ICMP, `6` = TCP, `17` = UDP).
- **Source IP (4 bytes)** & **Destination IP (4 bytes)**.

### 4. Transport Layer (Layer 4)
- **TCP (Transmission Control Protocol)**: Connection-oriented, reliable transport.
  - **Source & Destination Ports** (e.g. 80 = HTTP, 443 = HTTPS).
  - **Sequence & Acknowledgment Numbers** for ordered byte stream delivery.
  - **Flags**: `SYN` (Synchronize connection), `ACK` (Acknowledge), `FIN` (Finish connection), `RST` (Reset connection), `PSH` (Push data immediately).
- **UDP (User Datagram Protocol)**: Connectionless, lightweight transport for DNS, streaming, voice.
- **ICMP (Internet Control Message Protocol)**: Diagnostic/control messages (e.g., `Type 8` = Echo Request / Ping, `Type 0` = Echo Reply).

### 5. Application Layer (Layer 7) & Payload
- Standard text protocols (HTTP GET/POST) and binary streams (TLS/SSL Handshakes, DNS Queries).
- The sniffer provides a Wireshark-style **Hex Dump + ASCII view** of raw payload bytes.

---

## 🚀 Features

- **Dual Capture Engines**:
  - `Scapy Engine` (`scapy`): High-level sniffing, BPF filter parsing, `.pcap` export/import.
  - `Raw Socket Engine` (`socket`): Low-level standard library socket capture and bitwise binary unpacking via `struct.unpack`.
- **Packet Filtering**: Filter packets by BPF syntax (`tcp port 80`, `udp`, `icmp`, `ip`).
- **3 Verbosity Levels**:
  - `summary`: One-line clean overview of live packets.
  - `detailed`: Full multi-line OSI layer breakdown.
  - `hex`: Hexadecimal and ASCII payload rendering.
- **Traffic Analytics**: Displays top talker source/destination IPs, protocol distributions, bandwidth consumption, and top ports.
- **Offline PCAP Analysis**: Read and dissect existing `.pcap` files without admin privileges.
- **Exporting**: Save logs as `.pcap` files or structured `.json` datasets.

---

## 🛠️ Usage Instructions

### 1. Install Dependencies
```bash
py -m pip install -r requirements.txt
```

### 2. List Available Network Interfaces
```bash
py sniffer.py --list-interfaces
```

### 3. Basic Live Packet Capture (Summary View)
```bash
py sniffer.py -c 20
```

### 4. Capture TCP Traffic on Port 80 with Detailed Layer Breakdown
```bash
py sniffer.py -f "tcp port 80" -v detailed -c 10
```

### 5. Capture ICMP (Ping) Packets & Display Hex Payload
```bash
py sniffer.py -f "icmp" -v hex
```

### 6. Save Captured Traffic to PCAP File
```bash
py sniffer.py -c 50 -w capture.pcap
```

### 7. Read and Analyze PCAP File (No Admin Privileges Required)
```bash
py sniffer.py -r capture.pcap -v detailed
```

### 8. Export Packet Logs to JSON Format
```bash
py sniffer.py -c 25 -w packets.json
```

---

## 🔒 Privileges Notice
- **Windows**: Live packet capture requires running terminal as **Administrator**. WinPcap or Npcap is recommended for Scapy promiscuous mode.
- **Linux/macOS**: Live packet capture requires `sudo` / root privileges (`sudo py sniffer.py`).
- **Offline Mode (`-r capture.pcap`)**: Works without elevated privileges on all operating systems.

---

## 🧪 Automated Testing
Run unit tests to verify header parsing, ARP handling, and hexdump functions:
```bash
py -m pytest tests/test_sniffer.py -v
```
