#pragma once
#include <string>
#include <vector>
#include <cstdint>

// Attempts to extract the SNI hostname from a TLS Client Hello payload.
// Returns empty string if not found or payload is malformed.
std::string extract_sni(const std::vector<uint8_t>& payload);
