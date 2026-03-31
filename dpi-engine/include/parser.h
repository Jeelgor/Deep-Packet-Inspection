#pragma once
#include "packet.h"
#include <vector>
#include <string>

// Parses all packets from a PCAP file.
// Returns a list of parsed Packet structs.
std::vector<Packet> parse_pcap(const std::string& filepath);
