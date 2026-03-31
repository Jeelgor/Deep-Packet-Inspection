#include "parser.h"
#include "flow_tracker.h"
#include "packet_queue.h"
#include "ui.h"

#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <string>

static constexpr int CLEANUP_INTERVAL  = 100;
static constexpr int FLOW_TIMEOUT_SECS = 120; // keep flows visible for 2 minutes

// FILE mode: read all packets from PCAP then finish
void capture_file_thread(const std::string& filepath, PacketQueue& queue) {
    try {
        auto packets = parse_pcap(filepath);
        for (auto& pkt : packets)
            queue.push(std::move(pkt));
    } catch (const std::exception& e) {
        fprintf(stderr, "[capture] Error: %s\n", e.what());
    }
    queue.finish();
}

// LIVE mode: capture from interface until stopped
void capture_live_thread(const std::string& device,
                          PacketQueue& queue,
                          const std::atomic<bool>& stop) {
    capture_live(device, queue, stop);
}

void worker_thread(PacketQueue& queue, FlowTracker& tracker) {
    int processed = 0;
    while (true) {
        auto pkt = queue.pop();
        if (!pkt) break;
        tracker.processPacket(*pkt);
        if (++processed % CLEANUP_INTERVAL == 0)
            tracker.cleanupExpiredFlows(FLOW_TIMEOUT_SECS);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  dpi_engine <file.pcap>          read from PCAP file\n"
                  << "  dpi_engine --live <interface>   capture live traffic\n"
                  << "  dpi_engine --list               list network interfaces\n";
        return 1;
    }

    std::string arg1 = argv[1];

    // List interfaces mode — must be handled before UI starts
    if (arg1 == "--list") {
        list_interfaces();
        return 0;
    }

    PacketQueue        queue;
    FlowTracker        tracker;
    std::atomic<bool>  stop{false};
    std::atomic<bool>  done{false};
    bool               live_mode = (arg1 == "--live");

    // Start capture thread
    std::thread cap;
    if (live_mode) {
        if (argc < 3) {
            std::cerr << "Usage: dpi_engine --live <interface>\n";
            return 1;
        }
        std::string device = argv[2];
        cap = std::thread(capture_live_thread, device, std::ref(queue), std::ref(stop));
    } else {
        cap = std::thread(capture_file_thread, arg1, std::ref(queue));
    }

    // Start worker threads
    std::vector<std::thread> workers;
    for (int i = 0; i < 2; ++i)
        workers.emplace_back(worker_thread, std::ref(queue), std::ref(tracker));

    // Monitor thread: waits for processing to finish, sets done
    std::thread monitor([&]() {
        cap.join();
        for (auto& w : workers) w.join();
        tracker.cleanupExpiredFlows(FLOW_TIMEOUT_SECS);
        // In file mode, don't auto-exit — let user press 'q'
        // In live mode, done stays false until user presses 'q'
        if (live_mode) {
            // live mode: stop flag was set by UI, just mark done
            done = true;
        }
        // file mode: done stays false, UI keeps rendering until 'q'
    });

    // UI runs on main thread — stops on 'q' or done
    run_ui(tracker, done, stop);

    monitor.join();
    return 0;
}
