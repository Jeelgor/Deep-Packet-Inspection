#pragma once
#include "packet.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

// Thread-safe queue for passing Packets from capture thread to workers.
class PacketQueue {
public:
    // Push a packet onto the queue.
    void push(Packet pkt) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(pkt));
        }
        cv_.notify_one();
    }

    // Block until a packet is available or the queue is done.
    // Returns std::nullopt when done and queue is empty.
    std::optional<Packet> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !queue_.empty() || done_; });
        if (queue_.empty()) return std::nullopt;
        Packet pkt = std::move(queue_.front());
        queue_.pop();
        return pkt;
    }

    // Signal that no more packets will be pushed.
    void finish() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            done_ = true;
        }
        cv_.notify_all(); // wake all waiting workers
    }

private:
    std::queue<Packet>      queue_;
    std::mutex              mutex_;
    std::condition_variable cv_;
    bool                    done_ = false;
};
