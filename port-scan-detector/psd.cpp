#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include <map>
#include <set>
#include <string>

const int DISTINCT_PORTS_NUMBER_SCAN_TRESHOLD = 25;

using std::map;
using std::set;
using std::string;

map<string, set<u_short>> udp_m, hl_m, xmas_m, null_m;
map<string, int> udp_cnt, hl_cnt, xmas_cnt, null_cnt, icmp_cnt;

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
    struct ether_header *eth_header = (struct ether_header *)packet_body;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    int ethernet_header_length = 14;
    
    const u_char *ip_header = packet_body + ethernet_header_length;
    int ip_header_length = ((*ip_header) & 0x0F) * 4;
    struct ip *ip_header_struct = (struct ip*)ip_header;

    char src_ip[INET_ADDRSTRLEN + 5];
    char dst_ip[INET_ADDRSTRLEN + 5];

    inet_ntop(AF_INET, &(ip_header_struct->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header_struct->ip_dst), dst_ip, INET_ADDRSTRLEN);

    //printf("Source IP: %s\n", src_ip);
    //printf("Destination IP: %s\n", dst_ip);

    u_char protocol = ip_header_struct->ip_p;
    
    string map_form = string(src_ip) + ":" + string(dst_ip);

    if (protocol == IPPROTO_TCP) {
        //puts("TCP");
        const u_char *tcp_header = packet_body + ethernet_header_length + ip_header_length;
        struct tcphdr *tcp_header_struct = (struct tcphdr *)tcp_header;

        u_short p_src = ntohs(tcp_header_struct->source);
        u_short p_dst = ntohs(tcp_header_struct->dest);

        u_short c_ack = ntohs(tcp_header_struct->ack);
        u_short c_syn = ntohs(tcp_header_struct->syn);
        u_short c_psh = ntohs(tcp_header_struct->psh);
        u_short c_urg = ntohs(tcp_header_struct->urg);
        u_short c_rst = ntohs(tcp_header_struct->rst);
        u_short c_fin = ntohs(tcp_header_struct->fin);

        if (!c_ack && !c_syn && !c_psh && !c_urg && !c_rst && !c_fin) {
            printf("Null Scan detected from %s to %s:%hu\n", src_ip, dst_ip, p_dst);
            null_m[map_form].insert(p_dst);
            null_cnt[map_form]++;
        } else if (!c_ack && !c_syn && c_psh && c_urg && !c_rst && c_fin) {
            printf("Xmas Scan detected from %s to %s:%hu\n", src_ip, dst_ip, p_dst);
            xmas_m[map_form].insert(p_dst);
            xmas_cnt[map_form]++;
        } else if (!c_ack && c_syn && !c_psh && !c_urg && !c_rst && !c_fin) {
            auto &ps = hl_m[map_form];
            hl_cnt[map_form]++;
            if (ps.size() <= DISTINCT_PORTS_NUMBER_SCAN_TRESHOLD - 2) {
                ps.insert(p_dst);
            } else if (ps.size() == DISTINCT_PORTS_NUMBER_SCAN_TRESHOLD - 1) {
                ps.insert(p_dst);
                for (u_short i : ps) {
                    printf("Half-Open or Connect Scan is detected from %s to %s:%hu\n", src_ip, dst_ip, i);
                }
            } else if (!ps.count(p_dst)) {
                printf("Half-Open or Connect Scan is detected from %s to %s:%hu\n", src_ip, dst_ip, p_dst);
                ps.insert(p_dst);
            }
        }
    } else if (protocol == IPPROTO_UDP) {
        //puts("UDP");
        const u_char *udp_header = packet_body + ethernet_header_length + ip_header_length;
        struct udphdr *udp_header_struct = (struct udphdr *)udp_header;
        
        u_short p_src = ntohs(udp_header_struct->source);
        u_short p_dst = ntohs(udp_header_struct->dest);

        auto &ps = udp_m[map_form];
        udp_cnt[map_form]++;
        if (ps.size() <= DISTINCT_PORTS_NUMBER_SCAN_TRESHOLD - 2) {
            ps.insert(p_dst);
        } else if (ps.size() == DISTINCT_PORTS_NUMBER_SCAN_TRESHOLD - 1) {
            ps.insert(p_dst);
            for (u_short i : ps) {
                printf("Udp Scan is detected from %s to %s:%hu\n", src_ip, dst_ip, i);
            }
        } else if (!ps.count(p_dst)) {
            printf("Udp Scan is detected from %s to %s:%hu\n", src_ip, dst_ip, p_dst);
            ps.insert(p_dst);
        }
    } else if (protocol == IPPROTO_ICMP) {
        //puts("ICMP");
        const u_char *icmp_header = packet_body + ethernet_header_length + ip_header_length;
        struct icmphdr *icmp_header_struct = (struct icmphdr *)icmp_header;

        u_char c_type = icmp_header_struct->type;


        if (c_type == 8) {
            printf("ICMP Echo Request detected from %s to %s\n", src_ip, dst_ip);
            icmp_cnt[map_form]++;
        }
    } else {
        return;
    }
}

int main(int argc, char **argv) {
    puts("Port Scan Detector");
 
    if (argc > 2) {
        puts(
            "Usage:\n"
            "\n"
            "sudo psd\n"
            "to live capture network data.\n"
            "sudo psd <filename>\n"
            "to scan through .pcap file.\n"
        );
        return 0;
    }
    
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (argc == 1) {
        char *device = NULL;
        int timeout_limit = 10000;

        device = pcap_lookupdev(error_buffer);
        if (device == NULL) {
            printf("Error finding device: %s\n", error_buffer);
            return 1;
        }
        printf("Network device found: %s\n", device);

        handle = pcap_open_live(device, BUFSIZ, 0, timeout_limit, error_buffer);
        if (handle == NULL) {
            printf("Could not open device %s: %s\n", device, error_buffer);
            return 1;
        }
        printf("Successfully opened device %s\n", device);
    } else {
        char *filename = argv[1];
        handle = pcap_open_offline(filename, error_buffer);
        if (handle == NULL) {
            printf("Could not open file %s: %s\n", filename, error_buffer);
            return 1;
        }
        printf("Successfully opened file %s\n", filename);
    }

    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    
    puts("\n----------------------------------  OVERALL  ----------------------------------\n");

    bool not_found = true;

    for (const auto& i: null_m) {
        not_found = false;
        printf(
            "Null Scans from %s to %s info:\n"
            "\tUnique ports scanned %d\n"
            "\tOverall ports scanned %d\n\n",
            i.first.substr(0, i.first.find(':')).c_str(),
            i.first.substr(i.first.find(':') + 1).c_str(),
            int(i.second.size()),
            null_cnt[i.first]
        );
    }

    for (const auto& i: xmas_m) {
        not_found = false;
        printf(
            "Xmas Scans from %s to %s info:\n"
            "\tUnique ports scanned %d\n"
            "\tOverall ports scanned %d\n\n",
            i.first.substr(0, i.first.find(':')).c_str(),
            i.first.substr(i.first.find(':') + 1).c_str(),
            int(i.second.size()),
            xmas_cnt[i.first]
        );
    }

    for (const auto& i: udp_m) {
        if (i.second.size() >= DISTINCT_PORTS_NUMBER_SCAN_TRESHOLD) {
            not_found = false;
            printf(
                "Udp Scans from %s to %s info:\n"
                "\tUnique ports scanned %d\n"
                "\tOverall ports scanned %d\n\n",
                i.first.substr(0, i.first.find(':')).c_str(),
                i.first.substr(i.first.find(':') + 1).c_str(),
                int(i.second.size()),
                udp_cnt[i.first]
            );
        }
    }

    for (const auto& i: hl_m) {
        if (i.second.size() >= DISTINCT_PORTS_NUMBER_SCAN_TRESHOLD) {
            not_found = false;
            printf(
                "Half-Open or Connect Scans from %s to %s info:\n"
                "\tUnique ports scanned %d\n"
                "\tOverall ports scanned %d\n\n",
                i.first.substr(0, i.first.find(':')).c_str(),
                i.first.substr(i.first.find(':') + 1).c_str(),
                int(i.second.size()),
                hl_cnt[i.first]
            );
        }
    }

    for (const auto& i: icmp_cnt) {
        not_found = false;
        printf(
            "ICMP Echo Requests from %s to %s info:\n"
            "\tOverall number of requests %d\n\n",
            i.first.substr(0, i.first.find(':')).c_str(),
            i.first.substr(i.first.find(':') + 1).c_str(),
            i.second
        );
    }

    if (not_found) {
        puts("No scans found.");
    }

    return 0;
}