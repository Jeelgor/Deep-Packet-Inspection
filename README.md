# Deep Packet Inspection (DPI) Engine

A C++ network analysis tool that captures and inspects network packets in real time,
tracks connections, identifies applications, and applies security policies — displayed
in a live terminal UI.

---

## Features

- Live packet capture via Npcap or offline PCAP file analysis
- Flow tracking using 5-tuple (src IP, dst IP, src port, dst port, protocol)
- SNI extraction from TLS Client Hello (identifies HTTPS domains)
- Traffic classification: DNS, HTTP, HTTPS, UNKNOWN
- Rule-based policy engine: ALLOW / BLOCK / LOG / THROTTLE
- Rate limiting based on total bytes per flow
- Flow timeout and cleanup
- Multithreaded: capture thread + worker threads + UI thread
- Live terminal UI using PDCurses with color-coded actions

---

## Project Structure

```
dpi-engine/
├── include/           # Header files
│   ├── packet.h       # Packet struct
│   ├── flow_key.h     # FlowKey — uniquely identifies a connection
│   ├── flow_tracker.h # FlowTracker — manages the flow table
│   ├── parser.h       # PCAP file + live capture
│   ├── packet_queue.h # Thread-safe packet queue
│   ├── policy.h       # Policy engine + rate limiter
│   ├── sni.h          # TLS SNI extractor
│   └── ui.h           # Terminal UI
├── src/               # Source files
│   ├── main.cpp       # Entry point + thread management
│   ├── parser.cpp     # Packet parsing (IP/TCP/UDP headers + payload)
│   ├── flow_tracker.cpp
│   ├── sni.cpp
│   ├── policy.cpp
│   └── ui.cpp
├── tools/
│   └── gen_pcap.cpp   # Test PCAP generator
└── Makefile
```

---

## Dependencies

- [Npcap](https://npcap.com/) — install the `.exe` runtime
- [Npcap SDK](https://npcap.com/#download) — extract to `npcap-sdk/` next to `dpi-engine/`
- [MSYS2](https://www.msys2.org/) with MinGW64

```bash
pacman -S mingw-w64-x86_64-gcc make mingw-w64-x86_64-pdcurses
```

---

## Build

```bash
cd dpi-engine
make
```

---

## Run

```bash
# Generate test data
g++ -std=c++17 -o tools/gen_pcap tools/gen_pcap.cpp
./tools/gen_pcap.exe

# File mode (offline analysis)
./dpi_engine.exe tools/sample.pcap

# List network interfaces
./dpi_engine.exe --list

# Live capture
./dpi_engine.exe --live "\Device\NPF_{YOUR-INTERFACE-GUID}"
```

Press `q` to exit.

---

## Output

```
DPI Flow Monitor [Live]
Press 'q' to quit

Source                Destination           Proto  Type    Domain        Action    Packets  Bytes
192.168.1.10:7001     142.250.80.46:443     TCP    HTTPS   youtube.com   BLOCK     2        252
192.168.1.10:6001     151.101.1.140:80      TCP    HTTP    -             THROTTLE  3        162
192.168.1.10:5001     8.8.8.8:53            UDP    DNS     -             ALLOW     2        84
```

Colors: Red = BLOCK, Yellow = THROTTLE, Cyan = LOG, Green = ALLOW
