#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>

// PCAP global header
struct PcapGlobalHeader {
    uint32_t magic_number  = 0xa1b2c3d4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    int32_t  thiszone      = 0;
    uint32_t sigfigs       = 0;
    uint32_t snaplen       = 65535;
    uint32_t network       = 1; // LINKTYPE_ETHERNET
};

// PCAP per-packet header
struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

#pragma pack(push, 1)
struct EthHeader {
    uint8_t  dst[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t  src[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint16_t type   = 0x0008; // 0x0800 little-endian = IPv4
};

struct IPv4Header {
    uint8_t  ver_ihl   = 0x45; // version=4, IHL=5
    uint8_t  tos       = 0;
    uint16_t tot_len;
    uint16_t id        = 0;
    uint16_t frag_off  = 0;
    uint8_t  ttl       = 64;
    uint8_t  protocol;
    uint16_t checksum  = 0;
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq      = 0;
    uint32_t ack      = 0;
    uint8_t  data_off = 0x50; // header length = 20 bytes
    uint8_t  flags    = 0x02; // SYN
    uint16_t window   = 0x0020;
    uint16_t checksum = 0;
    uint16_t urg_ptr  = 0;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum = 0;
};
#pragma pack(pop)

static uint16_t htons16(uint16_t v) {
    return (v >> 8) | (v << 8);
}

static void write_tls_packet(std::ofstream& f, uint32_t ts,
                              uint8_t sip[4], uint8_t dip[4],
                              uint16_t sport, uint16_t dport,
                              const std::string& sni_host) {
    // Build a minimal TLS Client Hello with SNI extension
    std::vector<uint8_t> sni_ext;
    uint16_t host_len     = static_cast<uint16_t>(sni_host.size());
    uint16_t sni_list_len = host_len + 3;  // type(1) + len(2) + name
    uint16_t ext_data_len = sni_list_len + 2; // list_len field(2) + list

    // SNI extension type 0x0000
    sni_ext.push_back(0x00); sni_ext.push_back(0x00);
    // extension data length
    sni_ext.push_back((ext_data_len >> 8) & 0xff);
    sni_ext.push_back(ext_data_len & 0xff);
    // SNI list length
    sni_ext.push_back((sni_list_len >> 8) & 0xff);
    sni_ext.push_back(sni_list_len & 0xff);
    // name type = host_name (0)
    sni_ext.push_back(0x00);
    // name length
    sni_ext.push_back((host_len >> 8) & 0xff);
    sni_ext.push_back(host_len & 0xff);
    // name bytes
    for (char c : sni_host) sni_ext.push_back(static_cast<uint8_t>(c));

    uint16_t ext_total = static_cast<uint16_t>(sni_ext.size());

    // Minimal Client Hello body
    std::vector<uint8_t> hello;
    // client version TLS 1.2
    hello.push_back(0x03); hello.push_back(0x03);
    // random (32 bytes)
    for (int i = 0; i < 32; i++) hello.push_back(0xAB);
    // session id length = 0
    hello.push_back(0x00);
    // cipher suites length = 2, one suite
    hello.push_back(0x00); hello.push_back(0x02);
    hello.push_back(0xC0); hello.push_back(0x2B);
    // compression methods length = 1, null
    hello.push_back(0x01); hello.push_back(0x00);
    // extensions length
    hello.push_back((ext_total >> 8) & 0xff);
    hello.push_back(ext_total & 0xff);
    // extensions
    hello.insert(hello.end(), sni_ext.begin(), sni_ext.end());

    // Handshake header: type(1) + length(3)
    uint32_t hs_len = static_cast<uint32_t>(hello.size());
    std::vector<uint8_t> handshake;
    handshake.push_back(0x01); // Client Hello
    handshake.push_back((hs_len >> 16) & 0xff);
    handshake.push_back((hs_len >> 8)  & 0xff);
    handshake.push_back(hs_len & 0xff);
    handshake.insert(handshake.end(), hello.begin(), hello.end());

    // TLS record header: type(1) + version(2) + length(2)
    uint16_t rec_len = static_cast<uint16_t>(handshake.size());
    std::vector<uint8_t> tls_record;
    tls_record.push_back(0x16);        // Handshake
    tls_record.push_back(0x03); tls_record.push_back(0x01); // TLS 1.0
    tls_record.push_back((rec_len >> 8) & 0xff);
    tls_record.push_back(rec_len & 0xff);
    tls_record.insert(tls_record.end(), handshake.begin(), handshake.end());

    // Now wrap in Ethernet + IP + TCP
    EthHeader  eth;
    IPv4Header ip;
    TCPHeader  tcp;

    uint16_t ip_total = sizeof(IPv4Header) + sizeof(TCPHeader) +
                        static_cast<uint16_t>(tls_record.size());
    ip.tot_len  = htons16(ip_total);
    ip.protocol = 6;
    memcpy(ip.src_ip, sip, 4);
    memcpy(ip.dst_ip, dip, 4);
    tcp.src_port = htons16(sport);
    tcp.dst_port = htons16(dport);

    uint32_t pkt_len = sizeof(EthHeader) + sizeof(IPv4Header) +
                       sizeof(TCPHeader) + tls_record.size();
    PcapPacketHeader ph{ ts, 0, pkt_len, pkt_len };

    f.write(reinterpret_cast<char*>(&ph),  sizeof(ph));
    f.write(reinterpret_cast<char*>(&eth), sizeof(eth));
    f.write(reinterpret_cast<char*>(&ip),  sizeof(ip));
    f.write(reinterpret_cast<char*>(&tcp), sizeof(tcp));
    f.write(reinterpret_cast<char*>(tls_record.data()), tls_record.size());
}

static void write_tcp_packet(std::ofstream& f, uint32_t ts,
                              uint8_t sip[4], uint8_t dip[4],
                              uint16_t sport, uint16_t dport) {
    EthHeader  eth;
    IPv4Header ip;
    TCPHeader  tcp;

    uint16_t ip_total = sizeof(IPv4Header) + sizeof(TCPHeader);
    ip.tot_len  = htons16(ip_total);
    ip.protocol = 6; // TCP
    memcpy(ip.src_ip, sip, 4);
    memcpy(ip.dst_ip, dip, 4);
    tcp.src_port = htons16(sport);
    tcp.dst_port = htons16(dport);

    uint32_t pkt_len = sizeof(EthHeader) + sizeof(IPv4Header) + sizeof(TCPHeader);
    PcapPacketHeader ph{ ts, 0, pkt_len, pkt_len };

    f.write(reinterpret_cast<char*>(&ph),  sizeof(ph));
    f.write(reinterpret_cast<char*>(&eth), sizeof(eth));
    f.write(reinterpret_cast<char*>(&ip),  sizeof(ip));
    f.write(reinterpret_cast<char*>(&tcp), sizeof(tcp));
}

static void write_udp_packet(std::ofstream& f, uint32_t ts,
                              uint8_t sip[4], uint8_t dip[4],
                              uint16_t sport, uint16_t dport) {
    EthHeader  eth;
    IPv4Header ip;
    UDPHeader  udp;

    uint16_t udp_len   = sizeof(UDPHeader);
    uint16_t ip_total  = sizeof(IPv4Header) + udp_len;
    ip.tot_len  = htons16(ip_total);
    ip.protocol = 17; // UDP
    memcpy(ip.src_ip, sip, 4);
    memcpy(ip.dst_ip, dip, 4);
    udp.src_port = htons16(sport);
    udp.dst_port = htons16(dport);
    udp.length   = htons16(udp_len);

    uint32_t pkt_len = sizeof(EthHeader) + sizeof(IPv4Header) + sizeof(UDPHeader);
    PcapPacketHeader ph{ ts, 0, pkt_len, pkt_len };

    f.write(reinterpret_cast<char*>(&ph),  sizeof(ph));
    f.write(reinterpret_cast<char*>(&eth), sizeof(eth));
    f.write(reinterpret_cast<char*>(&ip),  sizeof(ip));
    f.write(reinterpret_cast<char*>(&udp), sizeof(udp));
}

int main() {
    std::ofstream f("tools/sample.pcap", std::ios::binary);
    if (!f) throw std::runtime_error("Cannot create tools/sample.pcap");

    PcapGlobalHeader gh;
    f.write(reinterpret_cast<char*>(&gh), sizeof(gh));

    uint8_t ip1[4] = {192,168,1,10};   // your laptop
    uint8_t ip2[4] = {142,250,80,46};  // google server
    uint8_t ip3[4] = {8,8,8,8};        // google DNS
    uint8_t ip4[4] = {31,13,71,36};    // facebook server
    uint8_t ip5[4] = {151,101,1,140};  // reddit server
    uint8_t ip6[4] = {192,168,1,20};   // another device on your network

    // --- DNS queries (port 53) ---
    write_udp_packet(f, 1000, ip1, ip3, 5001, 53);   // lookup #1 → ALLOW
    write_udp_packet(f, 1001, ip1, ip3, 5001, 53);   // same flow, 2nd packet
    write_udp_packet(f, 1002, ip6, ip3, 5002, 53);   // different device DNS

    // --- HTTP traffic (port 80) ---
    write_tcp_packet(f, 1003, ip1, ip5, 6001, 80);   // reddit HTTP → LOG
    write_tcp_packet(f, 1004, ip1, ip5, 6001, 80);   // same flow, triggers THROTTLE (>100 bytes)
    write_tcp_packet(f, 1005, ip1, ip5, 6001, 80);   // 3rd packet

    // --- HTTPS: youtube.com (should be BLOCK) ---
    write_tls_packet(f, 1006, ip1, ip2, 7001, 443, "youtube.com");
    write_tls_packet(f, 1007, ip1, ip2, 7001, 443, "youtube.com"); // 2nd packet same flow

    // --- HTTPS: facebook.com (ALLOW — not in block list) ---
    write_tls_packet(f, 1008, ip1, ip4, 7002, 443, "facebook.com");

    // --- HTTPS: reddit.com (ALLOW) ---
    write_tls_packet(f, 1009, ip1, ip5, 7003, 443, "reddit.com");
    write_tls_packet(f, 1010, ip1, ip5, 7003, 443, "reddit.com");
    write_tls_packet(f, 1011, ip1, ip5, 7003, 443, "reddit.com"); // 3 packets → THROTTLE

    // --- HTTPS: google.com (ALLOW) ---
    write_tls_packet(f, 1012, ip6, ip2, 7004, 443, "google.com");

    // --- Unknown protocol flow (port 9999) → UNKNOWN / ALLOW ---
    write_tcp_packet(f, 1013, ip1, ip4, 8001, 9999);
    write_tcp_packet(f, 1014, ip1, ip4, 8001, 9999);

    f.close();
    printf("tools/sample.pcap created with 14 packets across 8 flows.\n");
    return 0;
}
