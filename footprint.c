#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#define Max 10

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet_data);

char *IP_arr[Max];
int port_arr[Max];

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char dev[] = "en0"; // 스니핑할 네트워크 인터페이스
    int count;

    // 네트워크 인터페이스 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    if (pcap_loop(handle, -1, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error in pcap_loop()\n");
        return 1;
    }

    pcap_close(handle);
    return 0;
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet_data) {
    struct ip *iph = (struct ip *)(packet_data + 14);                           // 이더넷 헤더 크기 14
    struct udphdr *udph = (struct udphdr *)(packet_data + 14 + iph->ip_hl * 4); // I./P 헤더 크기 iph->ip_hl * 4

    // IP 주소와 포트 번호 비교
    if (iph->ip_src.s_addr == inet_addr("10.21.20.153") && ntohs(udph->uh_sport) == 57392) {
        // UDP 데이터 출력
        unsigned char *udp_data = (unsigned char *)(packet_data + 14 + iph->ip_hl * 4 + sizeof(struct udphdr));
        int udp_data_len = pkthdr->len - (14 + iph->ip_hl * 4 + sizeof(struct udphdr));
        if (udp_data[0] == 0x43) {
            printf("X : ");
            printf("%02x ", udp_data[62]);
            printf("%02x ", udp_data[63]);
            printf("%02x ", udp_data[64]);
            printf("%02x ", udp_data[65]);

            printf("    Y : ");
            printf("%02x ", udp_data[66]);
            printf("%02x ", udp_data[67]);
            printf("%02x ", udp_data[68]);
            printf("%02x ", udp_data[69]);

            // for (int i = 0; i < udp_data_len; i++) {
            //     printf("%02x ", udp_data[i]);
            // }
            printf("\n");
        }
    }
}