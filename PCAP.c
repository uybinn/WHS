#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h" // 구조체 정의가 포함된 헤더 파일

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800은 IP 타입
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) { // TCP 프로토콜인 경우
            int ip_header_len = ip->iph_ihl * 4; // IP 헤더 길이 (바이트 단위)
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

            // 필요한 경우 TCP 헤더에서 더 많은 정보를 추가할 수 있습니다
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // TCP 패킷만 캡처하기 위한 필터 표현식
    bpf_u_int32 net;

    // 단계 1: NIC 이름이 ens33인 라이브 pcap 세션 열기
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "장치 %s 열기 실패: %s\n", "ens33", errbuf);
        return EXIT_FAILURE;
    }

    // 단계 2: filter_exp를 BPF 의사 코드로 컴파일
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "필터 %s 파싱 실패: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터 %s 설치 실패: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    // 단계 3: 패킷 캡처
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // 핸들 닫기
    return 0;
}
