#pragma once
#include "packet.h"
#include "packet_queue.h"
#include <vector>
#include <string>
#include <atomic>

// Read all packets from a PCAP file and return them.
std::vector<Packet> parse_pcap(const std::string& filepath);

// Capture live packets from a network interface and push into queue.
// Runs until stop == true.
void capture_live(const std::string& device,
                  PacketQueue& queue,
                  const std::atomic<bool>& stop);

// List available network interfaces.
void list_interfaces();
