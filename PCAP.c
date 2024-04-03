#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4;
            struct tcpheader *tcp = (struct tcpheader *)
                                    (packet + ip_header_len + sizeof(struct ethheader));

            printf("Ethernet 헤더\n");
            printf("  출발지 MAC: ");
            for (int i = 0; i < 6; ++i)
                printf("%02x ", eth->ether_shost[i]);
            printf("\n");
            printf("  목적지 MAC: ");
            for (int i = 0; i < 6; ++i)
                printf("%02x ", eth->ether_dhost[i]);
            printf("\n");

            printf("IP 헤더\n");
            printf("  출발지 IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("  목적지 IP: %s\n", inet_ntoa(ip->iph_destip));

            printf("TCP 헤더\n");
            printf("  출발지 포트: %u\n", ntohs(tcp->tcp_sport));
            printf("  목적지 포트: %u\n", ntohs(tcp->tcp_dport));
        }
    }
}

int main()
{
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, NULL);
    pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL)
    pcap_close(handle);

    return 0;
}
