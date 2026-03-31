#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum class Protocol { TCP, UDP, OTHER };

struct Packet {
    std::string          src_ip;
    std::string          dst_ip;
    uint16_t             src_port = 0;
    uint16_t             dst_port = 0;
    Protocol             protocol = Protocol::OTHER;
    uint32_t             packet_number = 0;
    uint32_t             size = 0;
    std::vector<uint8_t> payload;  // TCP/UDP payload bytes
};
