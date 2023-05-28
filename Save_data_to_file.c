#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#define FILTER_RULE "udp"
#define _CRT_SECURE_NO_WARNINGS
#define MAX_LINE_LENGTH 20
#define Max 10

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

struct Player_Info {
    int Player_Number;
    char IP_Addr[16];
    int port;
};

void print_data(const unsigned char *data, struct ip_header *);
void save_data_to_file(int x, int y, int player_num); // int형 좌표를 파일에 저장하는 함수

struct Player_Info *Player_Info_Array;                // player정보들을 담은 구조체배열
int player;                                           // 플레이어 수
int past_x[Max] = {
    0,
},
    past_y[Max] = {
        350,
}; // 이전 위치를 저장하는 변수 (처음에는 침대 위치 저장)
bool is_out[Max] = {
    false,
}; // 집 밖에 나와있는지 확인하는 변수
bool is_first[Max] = {
    false,
}; // 나와서 얻은 위치 데이터가 처음인지 확인하는 변수

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_t *adhandle;
    struct bpf_program fcode;
    struct pcap_pkthdr *header;
    int i = 0;
    int num = 0;
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
    int src_Port;
    Player_Info_Array = (struct Player_Info *)malloc(player * sizeof(struct Player_Info));

    for (int p = 0; p < player; p++) {
        printf("player[%d]정보 입력하세요\n", p + 1);
        Player_Info_Array[p].Player_Number = p + 1;

        printf("IP : ");
        scanf("%s", src_IP);
        strcpy(Player_Info_Array[p].IP_Addr, src_IP);

        printf("Port 입력 : ");
        scanf("%d", &src_Port);
        Player_Info_Array[p].port = src_Port;

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
            int offset = 14;
            pkt_data = pkt_data + offset;

            struct ip_header *ih = (struct ip_header *)pkt_data;
            offset = ih->ip_header_len * 4 + 8; // 5 * 4 + 8
            print_data(pkt_data + offset, ih);
        }
    }

    /* 네트워크 디바이스 종료 */
    pcap_close(adhandle);
    free(Player_Info_Array);

    return 0;
}

void print_data(const unsigned char *data, struct ip_header *ih) {
    char X_Str[10] = "";
    char Y_Str[10] = "";

    for (int idx = 0; idx < 2; idx++) { // 하위 Byte만 big endian을 따라 string에 저장
        sprintf(X_Str + idx * 2, "%.2x", data[65 - idx]);
        sprintf(Y_Str + idx * 2, "%.2x", data[69 - idx]);
    }

    int x = (int)strtol(X_Str, NULL, 16) - 17208;        // 16진수의 X데이터 int로 변환
    int y = 17781 + (-1 * (int)strtol(Y_Str, NULL, 16)); // 16진수의 Y데이터 int로 변환

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
    char file_name[50];

    // player별 text파일 생성
    sprintf(file_name, "Footprint_Player[%d].txt", player_num);

    if (!is_out[player_num - 1]) { // 집안에 있을 때
        for (int i = 1; i < player_num; i++)
            printf("\t\t\t\t");
        printf("Player[%d] in house\n", player_num);

        // 집안의 y데이터는 334 ~ 501이다.
        if (y < 334) { // 집 현관 도착
            past_x[player_num - 1] = x;
            past_y[player_num - 1] = y;

            is_out[player_num - 1] = !is_out[player_num - 1]; // 이제 외출한다
            is_first[player_num - 1] = true;
        }
        return;
    }

    else { // 집 밖에 있을 때
        // past_x[player_num-1], past_y[player_num-1]를 바꾸지않으면 위치 데이터의 연속된값을 구할 때 예외가 발생한다.
        if (is_first[player_num - 1]) { // 이제 막 나왔으면 past_x[player_num-1], past_y[player_num-1]의 값을 바꾼다.
            past_x[player_num - 1] = x;
            past_y[player_num - 1] = y;
            is_first[player_num - 1] = false;
        }

        // 파일 읽기 모드로 열기
        file = fopen(file_name, "r");
        if (file != NULL) {                  // file안에 데이터가 있다면

            char temp[MAX_LINE_LENGTH] = ""; // 임시 변수
            if (fgets(temp, sizeof(temp), file) == NULL) {
                printf("파일이 비었습니다.\n");
            }

            // 끊어진 데이터 채우기 위해 past_x[player_num-1], past_y[player_num-1] 값 저장
            char *token = strtok(temp, " ");
            past_x[player_num - 1] = atoi(token);
            token = strtok(NULL, " ");
            past_y[player_num - 1] = atoi(token);

            // 파일 닫기
            fclose(file);

            // 이상치 발생(past_x[player_num-1]와 x의 차이가 크면 집에 들어왔다고 판단)
            if (abs(past_x[player_num - 1] - x) > 400) { // 현관에 들어오면 past_x[player_num-1], past_y[player_num-1]값을 다시 바꾼다.
                past_x[player_num - 1] = 0;
                past_y[player_num - 1] = 350;
                is_out[player_num - 1] = !is_out[player_num - 1];
                return;
            }

            else {                                                                // 아직 밖에 있다.
                if (x == past_x[player_num - 1] && y != past_y[player_num - 1]) { // y축 이동
                    if (y < past_y[player_num - 1]) {                             // 6시 방향으로 이동중
                        for (int new_y = past_y[player_num - 1] - 1; new_y > y; new_y--) {
                            for (int i = 1; i < player_num; i++)
                                printf("\t\t\t\t");

                            printf("Player[%d] : (%d, %d)\n", player_num, x, new_y);

                            file = fopen(file_name, "w");
                            fprintf(file, "%d %d\n", x, new_y);
                            fclose(file);
                        }
                    } else { // 12시 방향으로 이동중
                        for (int new_y = past_y[player_num - 1] + 1; new_y < y; new_y++) {
                            for (int i = 1; i < player_num; i++)
                                printf("\t\t\t\t");

                            printf("Player[%d] : (%d, %d)\n", player_num, x, new_y);

                            file = fopen(file_name, "w");
                            fprintf(file, "%d %d\n", x, new_y);
                            fclose(file);
                        }
                    }
                } else if (x != past_x[player_num - 1] && y == past_y[player_num - 1]) { // x축 이동
                    if (x < past_x[player_num - 1]) {                                    // 9시 방향으로 이동중
                        for (int new_x = past_x[player_num - 1] - 1; new_x > x; new_x--) {
                            for (int i = 1; i < player_num; i++)
                                printf("\t\t\t\t");

                            printf("Player[%d] : (%d, %d)\n", player_num, new_x, y);

                            file = fopen(file_name, "w");
                            fprintf(file, "%d %d\n", new_x, y);
                            fclose(file);
                        }
                    } else { // 3시 방향으로 이동중
                        for (int new_x = past_x[player_num - 1] + 1; new_x < x; new_x++) {
                            for (int i = 1; i < player_num; i++)
                                printf("\t\t\t\t");

                            printf("Player[%d] : (%d, %d)\n", player_num, new_x, y);

                            file = fopen(file_name, "w");
                            fprintf(file, "%d %d\n", new_x, y);
                            fclose(file);
                        }
                    }
                }

                else if (x != past_x[player_num - 1] && y != past_y[player_num - 1]) { // 대각선 이동

                    if (x < past_x[player_num - 1]) {                                  // 왼쪽으로 이동중
                        if (y < past_y[player_num - 1]) {                              // 7시 방향으로 이동중
                            int new_y = past_y[player_num - 1] - 1;                    // 새로 찍힐 y값을 저장한 변수

                            for (int new_x = past_x[player_num - 1] - 1; new_x > x; new_x--) {
                                for (int i = 1; i < player_num; i++)
                                    printf("\t\t\t\t");

                                printf("Player[%d] : (%d, %d)\n", player_num, new_x, new_y);

                                file = fopen(file_name, "w");
                                fprintf(file, "%d %d\n", new_x, new_y);
                                fclose(file);

                                new_y--;
                            }
                        }

                        else { // 11시 방향으로 이동중
                            int new_y = past_y[player_num - 1] + 1;
                            for (int new_x = past_x[player_num - 1] - 1; new_x > x; new_x--) {
                                for (int i = 1; i < player_num; i++)
                                    printf("\t\t\t\t");

                                printf("Player[%d] : (%d, %d)\n", player_num, new_x, new_y);

                                file = fopen(file_name, "w");
                                fprintf(file, "%d %d\n", new_x, new_y);
                                fclose(file);

                                new_y++;
                            }
                        }
                    }

                    else {                                          // 오른쪽으로 이동중
                        if (y > past_y[player_num - 1]) {           // 1시 방향으로 이동중
                            int new_y = past_y[player_num - 1] + 1; // 새로 찍힐 y값을 저장한 변수

                            for (int new_x = past_x[player_num - 1] + 1; new_x < x; new_x++) {
                                for (int i = 1; i < player_num; i++)
                                    printf("\t\t\t\t");

                                printf("Player[%d] : (%d, %d)\n", player_num, new_x, new_y);

                                file = fopen(file_name, "w");
                                fprintf(file, "%d %d\n", new_x, new_y);
                                fclose(file);

                                new_y++;
                            }

                        } else {                                    // 5시 방향으로 이동중
                            int new_y = past_y[player_num - 1] - 1; // 새로 찍힐 y값을 저장한 변수

                            for (int new_x = past_x[player_num - 1] + 1; new_x < x; new_x++) {
                                for (int i = 1; i < player_num; i++)
                                    printf("\t\t\t\t");

                                printf("Player[%d] : (%d, %d)\n", player_num, new_x, new_y);

                                file = fopen(file_name, "w");
                                fprintf(file, "%d %d\n", new_x, new_y);
                                fclose(file);

                                new_y--;
                            }
                        }
                    }
                }
            }
        }
    }
    // 마지막 데이터 저장
    file = fopen(file_name, "w");
    fprintf(file, "%d %d\n", x, y);
    fclose(file);
}