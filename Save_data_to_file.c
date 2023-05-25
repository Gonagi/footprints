#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#define FILTER_RULE "udp"
#define _CRT_SECURE_NO_WARNINGS
#define MAX_LINES 100
#define MAX_LINE_LENGTH 20

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

struct Data {
    unsigned int x;
    unsigned int y;
};

struct Player_Info {
    int Player_Number;
    char IP_Addr[16];
    int port;
};

void print_data(const unsigned char *data, struct ip_header *);
void save_data_to_file(int x, int y, int player_num); // int형 좌표를 파일에 저장하는 함수

struct Player_Info *Player_Info_Array;                // player정보들을 담은 구조체배열
int player;                                           // 플레이어 수

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
    char errbuf[PCAP_ERRBUF_SIZE];
    const unsigned char *pkt_data;

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

    char src_IP[16];
    int *src_Port = (int *)malloc(player * sizeof(int));
    Player_Info_Array = (struct Player_Info *)malloc(player * sizeof(struct Player_Info));

    for (int p = 0; p < player; p++) {
        src_IP[p] = (char *)malloc(16 * sizeof(char));
        printf("player[%d]정보 입력하세요\n", p + 1);
        Player_Info_Array[p].Player_Number = p + 1;

        printf("IP : ");
        scanf("%s", src_IP);
        // Player_Info_Array[p].IP_Addr = (char*)malloc(16 * sizeof(char));
        strcpy(Player_Info_Array[p].IP_Addr, src_IP);

        printf("Port 입력 : ");
        scanf("%d", &src_Port[p]);
        Player_Info_Array[p].port = src_Port[p];

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

            struct ip_header *ih = (struct ip_header *)pkt_data;
            offset = ih->ip_header_len * 4 + 8; // 5 * 4 + 8
            print_data(pkt_data + offset, ih);
        }
    }

    /* 네트워크 디바이스 종료 */
    pcap_close(adhandle);

    // 메모리 해제
    // for (int p = 0; p < player; p++) {
    //    free(Player_Info_Array[p].IP_Addr);
    //}
    free(Player_Info_Array);

    return 0;
}

void print_data(const unsigned char *data, struct ip_header *ih) {
    char X_Str[10] = "";
    char Y_Str[10] = "";

    for (int idx = 0; idx < 2; idx++) {
        sprintf(X_Str + idx * 2, "%.2x", data[64 + idx]);
        sprintf(Y_Str + idx * 2, "%.2x", data[68 + idx]);
    }

    int x = (int)strtol(X_Str, NULL, 16); // 16진수의 X데이터 int로 변환
    int y = (int)strtol(Y_Str, NULL, 16); // 16진수의 Y데이터 int로 변환

    // 현재 데이터의 player number 찾기
    for (int p = 0; p < player; p++) {
        if (strcmp(inet_ntoa(ih->ip_srcaddr), Player_Info_Array[p].IP_Addr) == 0) {
            save_data_to_file(x, y, Player_Info_Array[p].Player_Number);
            break;
        }
    }
}

void save_data_to_file(int x, int y, int player_num) {
    FILE *file;
    char file_name[20];
    int past_x = -1, past_y = -1; // 이전 위치를 저장하는 변수
    int delete_count = 0;         // 지워야 하는줄 count한 변수

    // 기존 내용을 저장할 배열 준비
    char lines[MAX_LINES][MAX_LINE_LENGTH];
    int line_count = 0;

    sprintf(file_name, "Footprint_Player[%d].txt", player_num);

    // 파일 읽기 모드로 열기
    file = fopen(file_name, "r");
    if (file == NULL) { // 파일에 읽을 내용이 없을 떄

    } else {            // 파일에 읽을 내용이 있을 떄
        // 파일 내용 읽기
        char line[MAX_LINE_LENGTH];
        while (fgets(line, sizeof(line), file) != NULL) {
            // 기존 내용을 배열에 저장
            if (line_count < MAX_LINES) {
                strcpy(lines[line_count], line);
                char *token = strtok(lines[line_count], " ");
                past_x = atoi(token);
                token = strtok(NULL, " ");
                past_y = atoi(token);
                line_count++;
            }
        }
        if (x == past_x && y == past_y) // 이전 x,y와 현재 x,y가 같을 때
            return;

        if (x == past_x && y != past_y) // 이전 x와 현재 x가 같고 y는 다를 때
            delete_count = abs(y - past_y);

        else if (x != past_x && y == past_y) // 이전 x와 현재 x가 다르고 y는 같을 때
            delete_count = abs(x - past_x);

        else // 이전 x,y와 현재 x,y가 모두 다를 때
            delete_count = 5 * abs(x - past_x);

        // 파일 닫기
        fclose(file);
    }

    // 파일 쓰기 모드로 열기 (기존 내용이 지워짐)
    file = fopen(file_name, "w");
    if (file == NULL) {
        printf("파일을 열 수 없습니다.");
        return;
    }

    // 기존 내용 쓰기
    for (int i = 0; i < line_count - delete_count; i++) {
        fprintf(file, "%s", lines[i]);
    }

    if (x == past_x && y != past_y) { // 이전 x와 현재 x가 같고 y는 다를 때
        if (y < past_y) {
            for (int idx = past_y - 1; idx > y; idx--)
                fprintf(file, "%d %d\n", x, idx);
        } else {
            for (int idx = past_y + 1; idx < y; idx++)
                fprintf(file, "%d %d\n", x, idx);
        }
    }

    else if (x != past_x && y == past_y) { // 이전 x와 현재 x가 다르고 y는 같을 때
        if (x < past_x) {
            for (int idx = past_x - 1; idx > x; idx--)
                fprintf(file, "%d %d\n", idx, y);
        } else {
            for (int idx = past_x + 1; idx < x; idx++)
                fprintf(file, "%d %d\n", idx, y);
        }
    }

    else { // 이전 x,y와 현재 x,y가 모두 다를 때
        ;
    }

    fprintf(file, "%d %d\n", x, y);

    fclose(file);
}