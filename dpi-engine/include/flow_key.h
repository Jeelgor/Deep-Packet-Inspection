#pragma once
#include "packet.h"
#include <string>
#include <functional>

// Uniquely identifies a network flow (connection).
// Normalized so A→B and B→A map to the same key.
struct FlowKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
    Protocol    protocol;

    // Normalize: always put the "smaller" endpoint first
    // so forward and reverse traffic share the same key.
    static FlowKey make(const std::string& ip_a, uint16_t port_a,
                        const std::string& ip_b, uint16_t port_b,
                        Protocol proto) {
        FlowKey k;
        k.protocol = proto;
        if (ip_a < ip_b || (ip_a == ip_b && port_a <= port_b)) {
            k.src_ip = ip_a; k.src_port = port_a;
            k.dst_ip = ip_b; k.dst_port = port_b;
        } else {
            k.src_ip = ip_b; k.src_port = port_b;
            k.dst_ip = ip_a; k.dst_port = port_a;
        }
        return k;
    }

    bool operator==(const FlowKey& o) const {
        return src_ip   == o.src_ip   &&
               dst_ip   == o.dst_ip   &&
               src_port == o.src_port &&
               dst_port == o.dst_port &&
               protocol == o.protocol;
    }
};

// Custom hash so FlowKey works as an unordered_map key.
struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const {
        // Combine hashes of all fields using FNV-style mixing.
        auto h = std::hash<std::string>{};
        auto n = std::hash<uint16_t>{};
        auto p = std::hash<int>{};

        std::size_t seed = h(k.src_ip);
        seed ^= h(k.dst_ip)   + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= n(k.src_port) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= n(k.dst_port) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= p(static_cast<int>(k.protocol)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
    }
};
