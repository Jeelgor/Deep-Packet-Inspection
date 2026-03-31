#include "parser.h"
#include "flow_tracker.h"
#include "packet_queue.h"
#include "ui.h"

#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>

static constexpr int CLEANUP_INTERVAL  = 100;
static constexpr int FLOW_TIMEOUT_SECS = 30;

void capture_thread(const std::string& filepath, PacketQueue& queue) {
    try {
        auto packets = parse_pcap(filepath);
        fprintf(stderr, "[capture] parsed %zu packets\n", packets.size());
        for (auto& pkt : packets) {
            queue.push(std::move(pkt));
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "[capture] Error: %s\n", e.what());
    }
    queue.finish();
}

void worker_thread(int /*id*/, PacketQueue& queue, FlowTracker& tracker) {
    int processed = 0;
    while (true) {
        auto pkt = queue.pop();
        if (!pkt) break;
        tracker.processPacket(*pkt);
        if (++processed % CLEANUP_INTERVAL == 0) {
            tracker.cleanupExpiredFlows(FLOW_TIMEOUT_SECS);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: pcap_parser <file.pcap>\n";
        return 1;
    }

    PacketQueue  queue;
    FlowTracker  tracker;
    std::atomic<bool> done{false};

    // Start capture thread
    std::thread cap(capture_thread, std::string(argv[1]), std::ref(queue));

    // Start worker threads
    std::vector<std::thread> workers;
    for (int i = 0; i < 2; ++i) {
        workers.emplace_back(worker_thread, i + 1, std::ref(queue), std::ref(tracker));
    }

    // Run UI on main thread (blocks until 'q' or done)
    std::thread ui_thread([&]() {
        cap.join();
        for (auto& w : workers) w.join();
        tracker.cleanupExpiredFlows(FLOW_TIMEOUT_SECS);
        // Small delay so UI renders the final state before marking done
        std::this_thread::sleep_for(std::chrono::seconds(3));
        done = true;
    });

    run_ui(tracker, done);

    ui_thread.join();
    return 0;
}
