#pragma once
#include "flow_key.h"
#include "packet.h"
#include <unordered_map>
#include <cstdint>
#include <string>
#include <mutex>
#include <chrono>

using Clock     = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

// Stores statistics for a single flow.
struct FlowData {
    uint64_t    packet_count = 0;
    uint64_t    total_bytes  = 0;
    std::string app_type;
    std::string domain;
    std::string action;
    TimePoint   last_seen_time = Clock::now(); // updated on every packet
};

// Tracks all active flows. Thread-safe.
class FlowTracker {
public:
    // Process one packet: create or update its flow entry.
    void processPacket(const Packet& pkt);

    // Remove flows inactive longer than timeout_seconds.
    void cleanupExpiredFlows(int timeout_seconds = 30);

    // Print all flows to stdout in readable format.
    void printFlows() const;

    const std::unordered_map<FlowKey, FlowData, FlowKeyHash>& flows() const {
        return flows_;
    }

private:
    std::unordered_map<FlowKey, FlowData, FlowKeyHash> flows_;
    mutable std::mutex mutex_;
};
