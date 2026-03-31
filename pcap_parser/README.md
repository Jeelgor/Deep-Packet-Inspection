# DPI Flow Monitor

A C++ Deep Packet Inspection (DPI) system built with libpcap/Npcap.

## Features

- Packet parsing (IP, TCP, UDP headers + payload)
- Flow tracking with connection lifecycle management
- SNI extraction from TLS Client Hello
- Traffic classification (DNS, HTTP, HTTPS)
- Rule-based policy engine (ALLOW / BLOCK / LOG)
- Rate limiting (THROTTLE on byte threshold)
- Flow timeout / cleanup
- Multithreaded processing (capture + worker threads)
- Terminal UI using PDCurses

## Project Structure

| File | Purpose |
|------|---------|
| `packet.h` | Packet struct |
| `parser.h/cpp` | PCAP file parsing via libpcap |
| `flow_key.h` | FlowKey struct with hash + normalization |
| `flow_tracker.h/cpp` | Flow table, thread-safe tracking |
| `sni.h/cpp` | TLS SNI extraction |
| `policy.h/cpp` | Policy engine + rate limiting |
| `packet_queue.h` | Thread-safe packet queue |
| `ui.h/cpp` | PDCurses terminal UI |
| `main.cpp` | Entry point, threads |
| `gen_pcap.cpp` | Test PCAP generator |

## Dependencies

- [Npcap](https://npcap.com/) + Npcap SDK
- [MSYS2](https://www.msys2.org/) with MinGW64
- PDCurses: `pacman -S mingw-w64-x86_64-pdcurses`

## Build

```bash
make
```

## Generate test data

```bash
g++ -std=c++17 -o gen_pcap gen_pcap.cpp
./gen_pcap.exe
```

## Run

```bash
./pcap_parser.exe sample.pcap
```

Press `q` to exit the UI.
