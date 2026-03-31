# DPI Engine — Deep Packet Inspection System

A C++ network analysis tool that reads packet captures, tracks connections,
identifies applications, and applies security policies — all displayed in a
live terminal UI.

---

## What is DPI?

**Deep Packet Inspection (DPI)** examines network packets beyond just their
headers. A normal firewall sees: *"packet from 192.168.1.10 to 8.8.8.8"*.
DPI sees: *"this is a DNS query from your laptop to Google's DNS server"*.

Real-world uses:
- ISPs throttling BitTorrent traffic
- Enterprises blocking social media
- Parental controls blocking specific websites
- Security tools detecting malware

---

## How a Network Packet Works

Every packet is like a nested envelope:

```
[ Ethernet Header  ]  → who is on this local network (MAC addresses)
  [ IP Header      ]  → source/destination IP addresses
    [ TCP/UDP Header]  → source/destination ports
      [ Payload    ]  → actual data (webpage, DNS query, TLS handshake)
```

Our engine peels each layer to extract useful information.

---

## What is a Flow?

A **flow** (or connection) is identified by 5 values called the **5-tuple**:

| Field | Example | Meaning |
|-------|---------|---------|
| Source IP | 192.168.1.10 | Your computer |
| Destination IP | 142.250.80.46 | Google server |
| Source Port | 54321 | Your browser's random port |
| Destination Port | 443 | HTTPS service |
| Protocol | TCP | Reliable connection |

All packets sharing the same 5-tuple belong to the same conversation.
We normalize direction so A→B and B→A are treated as the same flow.

---

## What is SNI?

When you visit `https://youtube.com`, your browser sends a **TLS Client Hello**
before encryption starts. This message contains the domain name in plaintext —
called **SNI (Server Name Indication)**. We extract this to identify HTTPS traffic.

```
TLS Client Hello
└── Extensions
    └── SNI: "youtube.com"  ← we read this
```

---

## Actions

| Action | Meaning |
|--------|---------|
| ALLOW | Normal traffic, pass through |
| LOG | Suspicious, record but allow |
| THROTTLE | Too much data, rate limited |
| BLOCK | Blocked by policy rule |

Priority order: `BLOCK > THROTTLE > LOG > ALLOW`

---

## Project Structure

```
dpi-engine/
├── include/           # Header files (data structures + interfaces)
│   ├── packet.h       # Packet struct — holds parsed packet data
│   ├── flow_key.h     # FlowKey struct — uniquely identifies a connection
│   ├── flow_tracker.h # FlowTracker class — manages the flow table
│   ├── parser.h       # parse_pcap() — reads PCAP files
│   ├── packet_queue.h # Thread-safe queue between capture and workers
│   ├── policy.h       # Policy engine interface
│   ├── sni.h          # SNI extractor interface
│   └── ui.h           # Terminal UI interface
│
├── src/               # Implementation files
│   ├── main.cpp       # Entry point — starts threads, runs UI
│   ├── parser.cpp     # Reads PCAP, extracts IP/TCP/UDP headers + payload
│   ├── flow_tracker.cpp # Tracks flows, calls SNI + policy + rate limiter
│   ├── sni.cpp        # Parses TLS Client Hello to extract domain name
│   ├── policy.cpp     # Rule-based policy engine + rate limiting
│   └── ui.cpp         # PDCurses terminal UI — live flow table
│
├── tools/
│   └── gen_pcap.cpp   # Generates a test PCAP file with sample traffic
│
├── Makefile
├── .gitignore
└── README.md
```

---

## How Data Flows Through the System

```
PCAP file
    │
    ▼
[parser.cpp]          reads raw bytes, extracts IP/TCP/UDP headers
    │
    ▼
[PacketQueue]         thread-safe buffer between capture and workers
    │
    ▼
[flow_tracker.cpp]    groups packets into flows by 5-tuple
    │   │
    │   ├── [sni.cpp]      extracts domain from TLS Client Hello
    │   ├── [policy.cpp]   applies ALLOW/BLOCK/LOG rules
    │   └── rate limiter   sets THROTTLE if bytes exceed threshold
    │
    ▼
[ui.cpp]              displays live flow table with colors
```

---

## Threading Model

```
Thread 1: capture_thread   reads PCAP → pushes to PacketQueue
Thread 2: worker_thread 1  pops from queue → processPacket()
Thread 3: worker_thread 2  pops from queue → processPacket()
Main:     UI thread        reads flow table every 1s → renders screen
```

The flow table is protected by a `std::mutex` so workers can safely
update it while the UI reads it.

---

## Dependencies

- [Npcap](https://npcap.com/) — packet capture runtime (install the `.exe`)
- [Npcap SDK](https://npcap.com/#download) — headers + libs for compiling
- [MSYS2](https://www.msys2.org/) with MinGW64 toolchain
- PDCurses for terminal UI

```bash
pacman -S mingw-w64-x86_64-gcc make mingw-w64-x86_64-pdcurses
```

---

## Build & Run

```bash
# 1. Generate test traffic
cd tools
g++ -std=c++17 -o gen_pcap gen_pcap.cpp
./gen_pcap.exe          # creates sample.pcap

# 2. Build the engine
cd ..
make

# 3. Run
./dpi_engine.exe tools/sample.pcap
```

Press `q` to exit the UI.

---

## Sample Output

```
  DPI Flow Monitor
  Press 'q' to quit

  Source                Destination           Proto  Type    Domain        Action    Packets  Bytes
  192.168.1.10:7001     142.250.80.46:443     TCP    HTTPS   youtube.com   BLOCK     2        252
  192.168.1.10:6001     151.101.1.140:80      TCP    HTTP    -             THROTTLE  3        162
  192.168.1.10:7003     151.101.1.140:443     TCP    HTTPS   reddit.com    THROTTLE  3        378
  192.168.1.10:7002     31.13.71.36:443       TCP    HTTPS   facebook.com  ALLOW     1        126
  192.168.1.10:7004     142.250.80.46:443     TCP    HTTPS   google.com    ALLOW     1        126
  192.168.1.10:5001     8.8.8.8:53            UDP    DNS     -             ALLOW     2        84
  192.168.1.20:5002     8.8.8.8:53            UDP    DNS     -             ALLOW     1        42
  192.168.1.10:8001     31.13.71.36:9999      TCP    UNKNOWN -             ALLOW     2        108
```

Colors: Red = BLOCK, Yellow = THROTTLE, Cyan = LOG, Green = ALLOW
