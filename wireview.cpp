/*
 * CS 3516 Computer Networks - Project 2: WireView (starter code)
 *
 * This program reads a packet capture file and prints summary statistics.
 * It compiles without warnings. It is not correct.
 *
 * Your job is to audit it against the specification in the project handout,
 * using Wireshark as ground truth. Some code here that looks wrong is right.
 */

#include <pcap.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <iomanip>
#include <map>
#include <string>
#include <cstring>

struct CaptureStats {
    bool has_start = false;
    struct timeval start_time{};
    struct timeval end_time{};
    uint64_t total_packets = 0;

    uint64_t total_bytes = 0;
    uint32_t min_pkt_size = UINT32_MAX;
    uint32_t max_pkt_size = 0;

    std::map<std::string, uint64_t> eth_src_counts;
    std::map<std::string, uint64_t> eth_dst_counts;

    std::map<std::string, uint64_t> ip_src_counts;
    std::map<std::string, uint64_t> ip_dst_counts;

    // ARP participants: MAC address -> IPv4 address
    std::map<std::string, std::string> arp_participants;

    std::map<uint16_t, uint64_t> udp_src_ports;
    std::map<uint16_t, uint64_t> udp_dst_ports;
};

static std::string mac_to_string(const uint8_t *mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

static std::string ipv4_to_string(const uint8_t *ip_bytes) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip_bytes, buf, sizeof(buf));
    return std::string(buf);
}

void packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    auto *stats = reinterpret_cast<CaptureStats *>(user);

    if (!stats->has_start) {
        stats->start_time = pkthdr->ts;
        stats->has_start = true;
    }
    stats->end_time = pkthdr->ts;
    stats->total_packets++;

    // Packet size statistics
    uint32_t pkt_size = pkthdr->len;
    stats->total_bytes += pkt_size;
    if (pkt_size < stats->min_pkt_size) stats->min_pkt_size = pkt_size;
    if (pkt_size > stats->max_pkt_size) stats->max_pkt_size = pkt_size;

    // Ethernet header
    const auto *eth_hdr = reinterpret_cast<const struct ether_header *>(packet);
    std::string src_mac = mac_to_string(eth_hdr->ether_shost);
    std::string dst_mac = mac_to_string(eth_hdr->ether_dhost);

    stats->eth_src_counts[src_mac]++;
    stats->eth_dst_counts[dst_mac]++;

    uint16_t ether_type = eth_hdr->ether_type;

    if (ntohs(ether_type) == ETHERTYPE_IP) {

        // Verify that the Ethernet and minimum IPv4 headers exist.
        if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
            return;
        }

        // Copy IPv4 header into aligned local storage.
        struct ip ip_hdr_storage;

        std::memcpy(
            &ip_hdr_storage,
            packet + sizeof(struct ether_header),
            sizeof(struct ip)
        );

        const struct ip *ip_hdr = &ip_hdr_storage;

        if (ip_hdr->ip_v != 4) {
            return;
        }

        // Calculate actual IPv4 header length.
        size_t ip_header_len = ip_hdr->ip_hl * 4;

        if (ip_header_len < sizeof(struct ip)) {
            return;
        }

        size_t ip_offset = sizeof(struct ether_header);

        // Validate complete IPv4 header.
        if (pkthdr->caplen < ip_offset + ip_header_len) {
            return;
        }

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, sizeof(dst_ip));

        stats->ip_src_counts[src_ip]++;
        stats->ip_dst_counts[dst_ip]++;

        // UDP header
        if (ip_hdr->ip_p == IPPROTO_UDP) {

            size_t udp_offset = ip_offset + ip_header_len;

            if (pkthdr->caplen < udp_offset + sizeof(struct udphdr)) {
                return;
            }

            struct udphdr udp_hdr_storage;

            std::memcpy(
                &udp_hdr_storage,
                packet + udp_offset,
                sizeof(struct udphdr)
            );

            uint16_t sport = ntohs(udp_hdr_storage.uh_sport);
            uint16_t dport = ntohs(udp_hdr_storage.uh_dport);

            stats->udp_src_ports[sport]++;
            stats->udp_dst_ports[dport]++;
        }
    } else if (ntohs(ether_type) == ETHERTYPE_ARP) {
        // ARP header, then the address fields that follow it
        const auto *arp_hdr = reinterpret_cast<const struct arphdr *>(packet + sizeof(struct ether_header));
        const auto *arp_payload = reinterpret_cast<const uint8_t *>(arp_hdr) + sizeof(struct arphdr);

        // Sender hardware address (6 bytes), sender protocol address (4 bytes)
        std::string sha = mac_to_string(arp_payload);
        std::string spa = ipv4_to_string(arp_payload + 6);

        // Target hardware address (6 bytes), target protocol address (4 bytes)
        std::string tha = mac_to_string(arp_payload + 10);
        std::string tpa = ipv4_to_string(arp_payload + 16);

        stats->arp_participants[sha] = spa;
        stats->arp_participants[tha] = tpa;
    }
}

void print_report(const CaptureStats &stats) {
    char time_buf[64];
    struct tm *tm_info = localtime(&stats.start_time.tv_sec);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    std::cout << "=== WireView Packet Capture Summary ===\n";
    std::cout << "Start Time:    " << time_buf << "."
              << std::setfill('0') << std::setw(6) << stats.start_time.tv_usec << "\n";

    long sec_diff = stats.end_time.tv_sec - stats.start_time.tv_sec;
    long usec_diff = stats.end_time.tv_usec - stats.start_time.tv_usec;
    double duration = static_cast<double>(sec_diff) + (static_cast<double>(usec_diff) / 1e6);

    std::cout << "Duration:      " << std::fixed << std::setprecision(6) << duration << " seconds\n";
    std::cout << "Total Packets: " << stats.total_packets << "\n";

    if (stats.total_packets > 0) {
        double avg_size = static_cast<double>(stats.total_bytes) / stats.total_packets;
        std::cout << "Packet Sizes:  min=" << stats.min_pkt_size
                  << " B, max=" << stats.max_pkt_size
                  << " B, avg=" << std::fixed << std::setprecision(2) << avg_size << " B\n";
    }

    std::cout << "\n--- Ethernet Senders ---\n";
    for (const auto &kv : stats.eth_src_counts) {
        std::cout << "  " << kv.first << " : " << kv.second << "\n";
    }

    std::cout << "\n--- Ethernet Recipients ---\n";
    for (const auto &kv : stats.eth_dst_counts) {
        std::cout << "  " << kv.first << " : " << kv.second << "\n";
    }

    std::cout << "\n--- IPv4 Senders ---\n";
    for (const auto &kv : stats.ip_src_counts) {
        std::cout << "  " << kv.first << " : " << kv.second << "\n";
    }

    std::cout << "\n--- IPv4 Recipients ---\n";
    for (const auto &kv : stats.ip_dst_counts) {
        std::cout << "  " << kv.first << " : " << kv.second << "\n";
    }

    std::cout << "\n--- ARP Participants ---\n";
    for (const auto &kv : stats.arp_participants) {
        std::cout << "  MAC: " << kv.first << " -> IP: " << kv.second << "\n";
    }

    std::cout << "\n--- UDP Source Ports ---\n";
    for (const auto &kv : stats.udp_src_ports) {
        std::cout << "  " << kv.first << " : " << kv.second << "\n";
    }

    std::cout << "\n--- UDP Destination Ports ---\n";
    for (const auto &kv : stats.udp_dst_ports) {
        std::cout << "  " << kv.first << " : " << kv.second << "\n";
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        std::cerr << "Error opening pcap file: " << errbuf << "\n";
        return 1;
    }

    CaptureStats stats;
    if (pcap_loop(handle, -1, packet_callback, reinterpret_cast<u_char *>(&stats)) < 0) {
        std::cerr << "Error reading packets: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }

    print_report(stats);

    return 0;
}
