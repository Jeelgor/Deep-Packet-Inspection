#include "flow_tracker.h"
#include "sni.h"
#include "policy.h"
#include <iostream>

static const char* proto_str(Protocol p) {
    switch (p) {
        case Protocol::TCP:  return "TCP";
        case Protocol::UDP:  return "UDP";
        default:             return "OTHER";
    }
}

// Classify based on whichever port is a known service port.
static std::string classify(uint16_t port_a, uint16_t port_b) {
    for (uint16_t port : {port_a, port_b}) {
        switch (port) {
            case 53:  return "DNS";
            case 80:  return "HTTP";
            case 443: return "HTTPS";
            default:  break;
        }
    }
    return "UNKNOWN";
}

// Try SNI extraction — only on client→server direction (dst_port==443)
// and only if payload starts with 0x16 (TLS Handshake record)
static std::string try_extract_sni(const Packet& pkt) {
    if (pkt.protocol != Protocol::TCP) return {};
    if (pkt.dst_port != 443)           return {}; // only client→server
    if (pkt.payload.size() < 6)        return {};
    if (pkt.payload[0] != 0x16)        return {}; // must be TLS Handshake
    if (pkt.payload[5] != 0x01)        return {}; // must be Client Hello
    return extract_sni(pkt.payload);
}

void FlowTracker::processPacket(const Packet& pkt) {
    FlowKey key = FlowKey::make(
        pkt.src_ip, pkt.src_port,
        pkt.dst_ip, pkt.dst_port,
        pkt.protocol
    );

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flows_.find(key);
    if (it == flows_.end()) {
        FlowData data;
        data.app_type = classify(key.src_port, key.dst_port);
        data.packet_count = 1;
        data.total_bytes  = pkt.size;
        if (pkt.protocol == Protocol::TCP &&
            (pkt.dst_port == 443 || pkt.src_port == 443) &&
            !pkt.payload.empty()) {
            data.domain = try_extract_sni(pkt);
        }
        data.action         = evaluate_policy(data.app_type, data.domain);
        data.action         = apply_rate_limit(data.action, data.total_bytes);
        data.last_seen_time = Clock::now();
        flows_.emplace(key, data);
    } else {
        it->second.packet_count  += 1;
        it->second.total_bytes   += pkt.size;
        it->second.last_seen_time = Clock::now();
        if (it->second.domain.empty() && !pkt.payload.empty()) {
            std::string sni = try_extract_sni(pkt);
            if (!sni.empty()) {
                it->second.domain = sni;
                it->second.action = evaluate_policy(it->second.app_type, it->second.domain);
            }
        }
        // Re-apply rate limit on every update
        it->second.action = apply_rate_limit(it->second.action, it->second.total_bytes);
    }
}

static bool is_known_port(uint16_t port) {
    return port == 53 || port == 80 || port == 443;
}

void FlowTracker::cleanupExpiredFlows(int timeout_seconds) {
    auto now      = Clock::now();
    auto timeout  = std::chrono::seconds(timeout_seconds);

    std::lock_guard<std::mutex> lock(mutex_);

    for (auto it = flows_.begin(); it != flows_.end(); ) {
        auto idle = std::chrono::duration_cast<std::chrono::seconds>(
                        now - it->second.last_seen_time);
        if (idle >= timeout) {
            const auto& key = it->first;
            std::cout << "[cleanup] Expired flow: "
                      << key.src_ip << ":" << key.src_port
                      << " <-> "
                      << key.dst_ip << ":" << key.dst_port
                      << " (idle " << idle.count() << "s)\n";
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}

void FlowTracker::printFlows() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (flows_.empty()) {
        std::cout << "No flows tracked.\n";
        return;
    }

    std::cout << "\n--- Flow Table (" << flows_.size() << " flows) ---\n";
    for (const auto& [key, data] : flows_) {
        // Always print: client <-> server
        // Server side is whichever has the known/lower service port.
        bool src_is_server = is_known_port(key.src_port) && !is_known_port(key.dst_port);

        const std::string& client_ip   = src_is_server ? key.dst_ip   : key.src_ip;
        uint16_t           client_port = src_is_server ? key.dst_port : key.src_port;
        const std::string& server_ip   = src_is_server ? key.src_ip   : key.dst_ip;
        uint16_t           server_port = src_is_server ? key.src_port : key.dst_port;

        std::cout
            << client_ip << ":" << client_port
            << " <-> "
            << server_ip << ":" << server_port
            << " (" << proto_str(key.protocol) << ")"
            << "  Type: "    << data.app_type
            << (data.domain.empty() ? "" : "  Domain: " + data.domain)
            << "  Action: "  << data.action
            << "  Packets: " << data.packet_count
            << ", Bytes: "   << data.total_bytes
            << "\n";
    }
}
