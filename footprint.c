#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>

#define FILTER_RULE "udp"
#define _CRT_SECURE_NO_WARNINGS

#pragma warning(disable : 4996)
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

struct ip_header {
    unsigned char ip_header_len : 4;
    unsigned char ip_version : 4;
    unsigned char ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned short ip_frag_offset;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_checksum;
    struct in_addr ip_srcaddr;
    struct in_addr ip_destaddr;
};

#pragma pack(push, 1)               // 패딩 설정을 변경하고 이전 설정을 스택에 저장
struct data_header {
    unsigned char data_43;          // 1
    unsigned short data_squence;    // 2
    unsigned short data_type;       // 2
    unsigned char data_messagetype; // 1
    unsigned long long data_userid; // 8
    unsigned int data_len;          // 4
};                                  // 18
#pragma pack(pop)                   // 이전 패딩 설정을 복원

int print_ip_header(const unsigned char *data);
void print_data(const unsigned char *data);

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_t *adhandle;
    struct bpf_program fcode;
    struct pcap_pkthdr *header;
    int i = 0;
    int num = 0;
    int offset = 14;
    int res;
    int player; // 플레이어 수
    char errbuf[PCAP_ERRBUF_SIZE];
    const unsigned char *pkt_data;
    char valX[5] = {};
    char valY[5] = {};

    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        return 1;
    }

    /* Print the list */
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return 0;
    }

    printf("Enter the interface number (1~%d) : ", i);
    scanf_s("%d", &num);

    /* 입력값의 유효성판단 */
    if (num < 1 || num > i) {
        printf("\nInterface number out of range\n");
        /* 장치  목록 해제 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 사용자가 선택한 디바이스 선택 */
    // Single Linked List 이므로 처음부터 순회하여 선택한 걸 찾음
    for (d = alldevs, i = 0; i < num - 1; d = d->next, i++)
        ;

    /* 선택한 실제 네트워크 디바이스 오픈 */
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 장치 목록 해제 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("Enter the number of players: ");
    scanf("%d", &player);

    char **src_IP = (char **)malloc(player * sizeof(char *));
    int *src_Port = (int *)malloc(player * sizeof(int));

    for (int p = 0; p < player; p++) {
        src_IP[p] = (char *)malloc(16 * sizeof(char));
        printf("player[%d]정보 입력하세요\n", p + 1);
        printf("IP : ");
        scanf("%s", src_IP[p]);
        printf("Port 입력 : ");
        scanf("%d", &src_Port[p]);
        printf("\n");
    }

    if (pcap_compile(adhandle,    // pcap handle
                     &fcode,      // compiled rule
                     FILTER_RULE, // filter rule (udp)
                     1,           // optimize
                     NULL) < 0) {
        printf("pcap compile failed\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (pcap_setfilter(adhandle, &fcode) < 0) {
        printf("pcap compile failed\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* We don't need any more the device list. Free it */
    // 선택된 디바이스를 pcap_open_live로 열고 그것을 제어하기 위한 Handle을 받았으므로
    // 더 이상 그 디바이스에 대한 정보가 필요없다.
    // pcap_findalldevs를 통해 생성된 Linked List 삭제
    pcap_freealldevs(alldevs);

    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
        if (res == 0) {
            printf("No PACKET\n");
            continue;
        }

        if ((pkt_data[45] == 0x50) && (pkt_data[46] == 0x02)) { // 이동데이터 조건
            pkt_data = pkt_data + offset;
            print_ip_header(pkt_data);
        }
    }

    /* 패킷 캡쳐 시작 */
    // 인자1 : pcap_open_live를 통해 얻은 네트워크 디바이스 핸들
    // 인자2 : 0=무한루프, 양의 정수=캡쳐할 패킷수
    // 인자3 : 패킷이 캡쳐되었을때, 호출될 함수 핸들러
    // 인자4 : 콜백함수로 넘겨줄 파라미터
    // pcap_loop(adhandle, 0, packet_handler, NULL);

    /* 네트워크 디바이스 종료 */
    pcap_close(adhandle);

    return 0;
}

int print_ip_header(const unsigned char *data) {
    struct ip_header *ih = (struct ip_header *)data;

    printf("\n============IP HEADER============\n");
    printf("Src IP Addr : %s\n", inet_ntoa(ih->ip_srcaddr));
    printf("Dst IP Addr : %s\n", inet_ntoa(ih->ip_destaddr));
    int offset = ih->ip_header_len * 4 + 8; // 5 * 4 + 8
    print_data(data + offset);

    return 0;
}

void print_data(const unsigned char *data) {
    printf("\n============DATA============\n");

    for (int a = 0; a < 79; a++) {
        printf("%.2x ", data[a]);

        if ((a + 1) % 16 == 0)
            printf("\n");
        else if ((a + 1) % 8 == 0)
            printf("\t");
    }

    printf("\n============LOCATION============\n");

    printf("X : ");
    for (int j = 0; j < 4; j++)
        printf("%.2x ", data[62 + j]);
    printf("\n");

    printf("Y : ");
    for (int j = 0; j < 4; j++)
        printf("%.2x ", data[66 + j]);
    printf("\n");
}