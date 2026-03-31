#include "parser.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>

#include <cstring>
#include <stdexcept>

// Minimal IP/TCP/UDP structs (normally from netinet/* on Linux)
struct ip {
    uint8_t  ip_hl:4, ip_v:4;
    uint8_t  ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t  ip_ttl;
    uint8_t  ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct tcphdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t  th_off:4, th_x2:4;
    uint8_t  th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

struct udphdr {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
};

// Ethernet header is 14 bytes; skip it to reach the IP header.
static constexpr int ETHERNET_HEADER_LEN = 14;

// Extract IP, TCP/UDP fields from a raw packet buffer.
static bool extract_packet(const u_char* data, uint32_t caplen, uint32_t number, Packet& out) {
    if (caplen < ETHERNET_HEADER_LEN + sizeof(struct ip)) {
        return false; // too short to contain an IP header
    }

    const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(data + ETHERNET_HEADER_LEN);

    // Only handle IPv4
    if (ip_hdr->ip_v != 4) {
        return false;
    }

    out.packet_number = number;
    char ip_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, ip_buf, sizeof(ip_buf));
    out.src_ip = ip_buf;
    inet_ntop(AF_INET, &ip_hdr->ip_dst, ip_buf, sizeof(ip_buf));
    out.dst_ip = ip_buf;

    int ip_header_len = ip_hdr->ip_hl * 4; // ip_hl is in 32-bit words
    const u_char* transport = data + ETHERNET_HEADER_LEN + ip_header_len;
    uint32_t transport_len  = caplen - ETHERNET_HEADER_LEN - ip_header_len;

    switch (ip_hdr->ip_p) {
        case IPPROTO_TCP: {
            if (transport_len < sizeof(struct tcphdr)) return false;
            const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(transport);
            out.src_port = ntohs(tcp->th_sport);
            out.dst_port = ntohs(tcp->th_dport);
            out.protocol = Protocol::TCP;
            // extract TCP payload
            // th_off is in the high nibble of the 12th byte of the TCP header
            uint32_t tcp_hdr_len = (transport[12] >> 4) * 4;
            if (tcp_hdr_len < transport_len) {
                const uint8_t* payload_start = transport + tcp_hdr_len;
                uint32_t       payload_len   = transport_len - tcp_hdr_len;
                out.payload.assign(payload_start, payload_start + payload_len);
            }
            break;
        }
        case IPPROTO_UDP: {
            if (transport_len < sizeof(struct udphdr)) return false;
            const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(transport);
            out.src_port = ntohs(udp->uh_sport);
            out.dst_port = ntohs(udp->uh_dport);
            out.protocol = Protocol::UDP;
            // extract UDP payload
            if (transport_len > sizeof(struct udphdr)) {
                const uint8_t* payload_start = transport + sizeof(struct udphdr);
                uint32_t       payload_len   = transport_len - sizeof(struct udphdr);
                out.payload.assign(payload_start, payload_start + payload_len);
            }
            break;
        }
        default:
            out.protocol = Protocol::OTHER;
            break;
    }

    return true;
}

std::vector<Packet> parse_pcap(const std::string& filepath) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_offline(filepath.c_str(), errbuf);
    if (!handle) {
        throw std::runtime_error(std::string("Failed to open PCAP file: ") + errbuf);
    }

    std::vector<Packet> packets;
    struct pcap_pkthdr* header;
    const u_char* data;
    uint32_t count = 0;

    int result;
    while ((result = pcap_next_ex(handle, &header, &data)) == 1) {
        ++count;
        Packet pkt;
        if (extract_packet(data, header->caplen, count, pkt)) {
            pkt.size = header->caplen;
            packets.push_back(pkt);
        }
    }

    if (result == -1) {
        pcap_close(handle);
        throw std::runtime_error(std::string("Error reading packets: ") + pcap_geterr(handle));
    }

    pcap_close(handle);
    return packets;
}
