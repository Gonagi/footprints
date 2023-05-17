/*
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#define Max 10

char *IP_arr[Max] = {""}; // 최대 'Max' 플레이어와 멀티맵 가능
int Port_arr[Max] = {0};  // 최대 'Max' 플레이어의 port번호 저장

int count;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *iph;
    struct udphdr *udph;

    iph = (struct ip *)(packet + 14);                       // Ethernet header size is 14 bytes
    udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4); // IP header size is ip_hl * 4 bytes

    unsigned short src_port = ntohs(udph->uh_sport);
    unsigned int src_ip = ntohl(iph->ip_src.s_addr);

    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);

    for (int idx = 0; idx < Max; idx++) {
        if (Port_arr[idx] != src_port) { // port_arr에 저장되어있지않은 값이면 IP_arr, port_arr에 저장
            Port_arr[idx] = src_port;
            IP_arr[idx] = src_ip_str;
            count = idx + 1; // 진짜 플레이어 수 저장
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("Device not found: %s\n", errbuf);
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't open device: %s\n", errbuf);
        return 1;
    }

    if (pcap_loop(handle, 30, packet_handler, NULL) < 0) { // 패킷 30개 받고 종료
        printf("Error in pcap_loop()\n");
        return 1;
    }

    pcap_close(handle);

    for (int idx = 0; idx < count; idx++) {
        printf("IP : %s\n", IP_arr[idx]);
        printf("Port : %d\n\n", Port_arr[idx]);
    }
    return 0;
}
*/

/*
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define Max 10

char *IP_arr[Max] = {NULL};
int Port_arr[Max] = {0};
int count = 0;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *iph;
    struct udphdr *udph;

    iph = (struct ip *)(packet + 14);
    udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);

    unsigned short src_port = ntohs(udph->uh_sport);
    unsigned int src_ip = ntohl(iph->ip_src.s_addr);

    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);

    // 중복 값 확인 및 저장
    int duplicate = 0;
    for (int idx = 0; idx < count; idx++) {
        if (Port_arr[idx] == src_port && strcmp(IP_arr[idx], src_ip_str) == 0) {
            duplicate = 1;
            break;
        }
    }

    if (!duplicate && count < Max) {
        IP_arr[count] = strdup(src_ip_str);
        Port_arr[count] = src_port;
        count++;
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("Device not found: %s\n", errbuf);
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't open device: %s\n", errbuf);
        return 1;
    }

    if (pcap_loop(handle, 30, packet_handler, NULL) < 0) {
        printf("Error in pcap_loop()\n");
        return 1;
    }

    pcap_close(handle);

    for (int idx = 0; idx < count; idx++) {
        printf("IP: %s\n", IP_arr[idx]);
        printf("Port: %d\n\n", Port_arr[idx]);
    }

    // 메모리 해제
    for (int idx = 0; idx < count; idx++) {
        free(IP_arr[idx]);
    }

    return 0;
}
*/

/*
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define Max 10

char *IP_arr[Max] = {NULL};
int Port_arr[Max] = {0};
int count = 0;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *iph;
    struct udphdr *udph;

    iph = (struct ip *)(packet + 14);
    udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);

    unsigned short src_port = ntohs(udph->uh_sport);
    unsigned int src_ip = ntohl(iph->ip_src.s_addr);

    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);

    // 패킷 길이 확인 및 중복 값 확인 및 저장
    int packet_length = pkthdr->caplen;
    int duplicate = 0;
    for (int idx = 0; idx < count; idx++) {
        if (Port_arr[idx] == src_port && strcmp(IP_arr[idx], src_ip_str) == 0) {
            duplicate = 1;
            break;
        }
    }

    if (packet_length == 79 && !duplicate && count < Max) {
        IP_arr[count] = strdup(src_ip_str);
        Port_arr[count] = src_port;
        count++;
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("Device not found: %s\n", errbuf);
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't open device: %s\n", errbuf);
        return 1;
    }

    if (pcap_loop(handle, 30, packet_handler, NULL) < 0) {
        printf("Error in pcap_loop()\n");
        return 1;
    }

    pcap_close(handle);

    for (int idx = 0; idx < count; idx++) {
        printf("IP: %s\n", IP_arr[idx]);
        printf("Port: %d\n\n", Port_arr[idx]);
    }

    // 메모리 해제
    for (int idx = 0; idx < count; idx++) {
        free(IP_arr[idx]);
    }

    return 0;
}
*/

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define Max 10

char *IP_arr[Max] = {NULL}; // IP주소 저장하는 배열
int Port_arr[Max] = {0};    // port번호 저장하는 배열
int count = 0;              // 실제 플레이하는 클라이언트 수

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *iph;
    struct udphdr *udph;

    iph = (struct ip *)(packet + 14);
    udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);

    unsigned short src_port = ntohs(udph->uh_sport);
    unsigned int src_ip = ntohl(iph->ip_src.s_addr);

    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);

    // 패킷 데이터 확인 및 중복 값 확인 및 저장
    u_char *data = (u_char *)(packet + 14 + iph->ip_hl * 4 + sizeof(struct udphdr));
    if (pkthdr->caplen > (sizeof(struct ip) + sizeof(struct udphdr)) && data[0] == 0x43) { // data[0] == 0x43 --> data[0]이 이동패킷을 뜻하는 C인 경우에만 배열에 저장한다.
        int duplicate = 0;
        for (int idx = 0; idx < count; idx++) {
            if (Port_arr[idx] == src_port && strcmp(IP_arr[idx], src_ip_str) == 0) { // IP주소, port번호가 기존 배열에 저장되어 있는지 확인
                duplicate = 1;
                break;
            }
        }

        if (!duplicate && count < Max) {
            IP_arr[count] = strdup(src_ip_str);
            Port_arr[count] = src_port;
            count++;
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("Device not found: %s\n", errbuf);
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't open device: %s\n", errbuf);
        return 1;
    }

    if (pcap_loop(handle, 100, packet_handler, NULL) < 0) { // 100개의 패킷만 받아 ip주소, port번호를 받아온다.
        printf("Error in pcap_loop()\n");
        return 1;
    }

    pcap_close(handle);

    for (int idx = 0; idx < count; idx++) {
        printf("IP: %s\n", IP_arr[idx]);
        printf("Port: %d\n\n", Port_arr[idx]);
    }

    // 메모리 해제
    for (int idx = 0; idx < count; idx++) {
        free(IP_arr[idx]);
    }

    return 0;
}
