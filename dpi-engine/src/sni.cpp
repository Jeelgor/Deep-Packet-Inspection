#include "sni.h"

// TLS record / handshake layout (simplified):
//
//  [0]      Content Type     (0x16 = Handshake)
//  [1-2]    TLS Version
//  [3-4]    Record Length
//  [5]      Handshake Type   (0x01 = Client Hello)
//  [6-8]    Handshake Length (3 bytes)
//  [9-10]   Client Version
//  [11-42]  Random (32 bytes)
//  [43]     Session ID Length
//  [44+]    Session ID
//  ...      Cipher Suites, Compression, Extensions
//
// We walk through extensions looking for type 0x0000 (SNI),
// then extract the hostname from it.

std::string extract_sni(const std::vector<uint8_t>& buf) {
    const uint8_t* p   = buf.data();
    size_t         len = buf.size();

    // Need at least a TLS record header (5) + handshake header (4)
    if (len < 9) return {};

    // Must be a TLS Handshake record
    if (p[0] != 0x16) return {};

    // Must be a Client Hello
    if (p[5] != 0x01) return {};

    size_t offset = 9; // skip record header (5) + handshake type (1) + length (3)

    // Skip client version (2) + random (32)
    offset += 2 + 32;
    if (offset >= len) return {};

    // Skip session ID
    uint8_t session_id_len = p[offset++];
    offset += session_id_len;
    if (offset + 2 > len) return {};

    // Skip cipher suites
    uint16_t cipher_len = (p[offset] << 8) | p[offset + 1];
    offset += 2 + cipher_len;
    if (offset + 1 > len) return {};

    // Skip compression methods
    uint8_t comp_len = p[offset++];
    offset += comp_len;
    if (offset + 2 > len) return {};

    // Extensions total length
    uint16_t ext_total = (p[offset] << 8) | p[offset + 1];
    offset += 2;

    size_t ext_end = offset + ext_total;
    if (ext_end > len) return {};

    // Walk extensions
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = (p[offset] << 8) | p[offset + 1];
        uint16_t ext_len  = (p[offset + 2] << 8) | p[offset + 3];
        offset += 4;

        if (ext_type == 0x0000) { // SNI extension
            // SNI list length (2) + entry type (1) + name length (2) + name
            if (offset + 5 > ext_end) return {};
            // skip SNI list length (2) and entry type (1)
            offset += 3;
            uint16_t name_len = (p[offset] << 8) | p[offset + 1];
            offset += 2;
            if (offset + name_len > ext_end) return {};
            return std::string(reinterpret_cast<const char*>(p + offset), name_len);
        }

        offset += ext_len;
    }

    return {}; // SNI not found
}
