#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string.h>

#define FILTER_RULE "udp"
#define _CRT_SECURE_NO_WARNINGS
#define MAX_LINE_LENGTH 20
#define Max 10

#pragma warning(disable:4996)
#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )

struct ip_header
{
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

struct udp_header
{
    unsigned short udp_srcport = 0;
    unsigned short udp_dstport = 0;
};


#pragma pack(push, 1)  // 패딩 설정을 변경하고 이전 설정을 스택에 저장
struct data_header
{
    unsigned char data_lidgren_type;//1
    unsigned short data_squence;//2
    unsigned short data_type;//2
    unsigned char data_messagetype;//1
    unsigned long long data_userid; //8
    unsigned int data_len;//4
    unsigned int header_len;
}; //18
#pragma pack(pop)  // 이전 패딩 설정을 복원

struct ip_header* check_ip_header(const unsigned char* data);
struct udp_header* check_udp_header(const unsigned char* data);
void set_offset(const unsigned char** pkt_data, int num);
void print_data(const unsigned char* data, int current_usr);
struct data_header* check_data_header(const unsigned char* data, int len);
int check_id(struct data_header* dh, long long* user_id_arr, int* current_usr);

int past_x[Max] = {
    0,
},
past_y[Max] = {
    350,
}; // 이전 위치를 저장하는 변수 (처음에는 침대 위치 저장)
bool is_out[Max] = {
    false,
}; // 집 밖에 나와있는지 확인하는 변수

FILE* fp[5] = { 0 };

int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_t* adhandle;
    struct bpf_program fcode;
    struct pcap_pkthdr* header;
    struct ip_header* ih = 0;
    struct udp_header* uh = 0;
    struct data_header* dh = 0;
    int i = 0; //네트워크 인터페이스 설정용
    unsigned int num = 0; //네트워크 인터페이스 설정용 나중에 offset 합 구하는데도 씀 ㅋㅋ
    int offset = 14; //헤더 내용 삭제할 때 사용할 offset
    int res; //패킷 캡쳐시 에러 확인용
    int client_num = 0;
    int current_usr = -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    const unsigned char* pkt_data;
    long long user_id_arr[5] = { 0 };
    char temp1[99];

    //Retrieve the device list from the local machine
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        return 1;
    }

    // Print the list
    for (d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return 0;
    }

    printf("Enter the interface number (1~%d) : ", i);
    scanf_s("%d", &num);

    // 입력값의 유효성판단
    if (num < 1 || num > i)
    {
        printf("\nInterface number out of range\n");
        // 장치  목록 해제
        pcap_freealldevs(alldevs);
        return -1;
    }

    // 사용자가 선택한 디바이스 선택
    // Single Linked List 이므로 처음부터 순회하여 선택한 걸 찾음
    for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);

    // 선택한 실제 네트워크 디바이스 오픈
    if ((adhandle = pcap_open_live(d->name, 65536, 1, 500, errbuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        // 장치 목록 해제
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (pcap_compile(adhandle,  // pcap handle
        &fcode,  // compiled rule
        FILTER_RULE,  // filter rule
        1,            // optimize
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

    // We don't need any more the device list. Free it
    // 선택된 디바이스를 pcap_open_live로 열고 그것을 제어하기 위한 Handle을 받았으므로
    // 더 이상 그 디바이스에 대한 정보가 필요없다.
    // pcap_findalldevs를 통해 생성된 Linked List 삭제
    pcap_freealldevs(alldevs);

    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        offset = 14;
        if (res <= 0)
        {
            //printf("No PACKET\n");
            continue;
        }
        set_offset(&pkt_data, offset);
        ih = check_ip_header(pkt_data); //ip 출력 및 ip 헤더구조체 리턴
        set_offset(&pkt_data, ih->ip_header_len * 4); //ip 영역 만큼 이동
        uh = check_udp_header(pkt_data);
        set_offset(&pkt_data, 8);

        if (uh->udp_srcport == (unsigned short)24642 || uh->udp_dstport == (unsigned short)24642)
        {

            num = 14 + (ih->ip_header_len * 4 + 8);

            while (1)
            {
                //header->len == 패킷의 길이가 저장된 변수
                dh = check_data_header(pkt_data, header->len);
                switch (check_id(dh, user_id_arr, &current_usr))
                {
                case -1: //유효하지 않는 패킷
                    num = header->len;
                    dh->header_len = 1;
                    dh->data_len = 1;
                    break;

                case 1: //connect
                    sprintf(temp1, "Footprint_Player[%d].txt", current_usr);
                    printf("id: %s && %llx\n", temp1, user_id_arr[current_usr]);
                    fp[current_usr] = fopen(temp1, "w");
                    printf("client_num == %d\n", current_usr);
                    if (fp[current_usr] == NULL)
                    {
                        printf("파일열기 실패\n");
                        return 0;
                    }
                    else
                    {
                        printf("파일열기 성공\n");
                        fclose(fp[current_usr]);
                        ++client_num;
                    }
                    num = header->len;
                    dh->header_len = 1;
                    dh->data_len = 1;
                    break;

                case 2: //연결 종료
                    sprintf(temp1, "Footprint_Player[%d].txt", current_usr);
                    user_id_arr[current_usr] = 0;
                    client_num--;
                    printf("user_id_index == %d\n", current_usr);
                    printf("user_id == %llx\n", user_id_arr[current_usr]);
                    printf("===========================================\n");
                    break;
                case 3: //유효한 패킷일 경우 타입에 맞춰서 데이터 처리
                    set_offset(&pkt_data, dh->header_len);
                    if (dh->data_lidgren_type == 0x43 && dh->data_type == 0x250)
                    {
                        print_data(pkt_data, current_usr);
                    }
                case 4: //헤더 구조는 맞지만 필요 없는 데이터 일 경우
                    break;
                case 5:
                    break;
                }
                set_offset(&pkt_data, dh->data_len);
                num = num + dh->header_len + dh->data_len;
                if (dh->header_len == 0 && dh->data_len == 0)//비정상적 처리일 경우, 패킷 내용과 헤더 내용 출력 후 종료
                {
                    for (int i = 0; i < header->len - num; i++)
                    {
                        printf("%.2x ", pkt_data[i]);
                        if ((i + 1) % 16 == 0)
                            printf("\n");
                        else if ((i + 1) % 8 == 0)
                            printf("    ");
                    }
                    printf("\n");
                    printf("udpport:%x(%d)->%x(%d)\n", uh->udp_srcport, uh->udp_srcport, uh->udp_dstport, uh->udp_dstport);
                    printf("\n==========DATA_HEADER==========\n");
                    printf("data_lidgren_type: %x\n", dh->data_lidgren_type);
                    printf("data_squence: %x\n", dh->data_squence);
                    printf("data_type: %x\n", dh->data_type);
                    printf("data_messagetype: %x\n", dh->data_messagetype);
                    printf("data_userid: %llx\n", dh->data_userid);
                    printf("datalen: %x\n", dh->data_len);
                    printf("header_len: %d\n", dh->header_len);
                    printf("\n==========HEADER_LEN-NUM==========\n");
                    printf("           %u     -      %u    =  %d\n", header->len, num, header->len - num);
                    exit(1);
                }
                if (header->len <= num)//다음 패킷 받을 준비
                {
                    pkt_data = 0;
                    header = 0;
                    break;
                }
                printf("==연결된 패킷 분리==\n");
            }
        }
    }
    printf("=============================================================\n  종료\n");
    // 네트워크 디바이스 종료
    pcap_close(adhandle);
    return 0;
}

struct ip_header* check_ip_header(const unsigned char* data)
{
    struct ip_header* ih;
    ih = (struct ip_header*)data;  
    //ip_header의 구조체 형태로 변환. 각 바이트 크기만큼 순서대로 값이 들어감
    return ih;
}

struct udp_header* check_udp_header(const unsigned char* data)
{
    struct udp_header* uh = 0;
    unsigned char chtemp = 0;
    unsigned short shtemp = 0;
    uh = (struct udp_header*)data;

    shtemp = uh->udp_dstport;
    chtemp = (shtemp >> 8);
    uh->udp_dstport = (shtemp << 8) + chtemp;

    shtemp = uh->udp_srcport;
    chtemp = (shtemp >> 8);
    uh->udp_srcport = (shtemp << 8) + chtemp;
    //2바이트이기 때문에, 앞 뒤 위치만 바꾸어줘도 endian을 바꿀 수 있다.
    return uh;
}

void set_offset(const unsigned char** pkt_data, int num)
{
    *pkt_data += num;
    return;
}

struct data_header* check_data_header(const unsigned char* data, int len)
{
    int result = 0;
    struct data_header* dh = 0;
    short* stp1 = 0;
    short* stp2 = 0;
    long long* id = 0;

    dh = (struct data_header*)data;

    switch (dh->data_lidgren_type)
    {
    case 67: //userreliableordered
        stp1 = (short*)(data + 10);
        stp2 = (short*)(data + 11);
        if (dh->data_type == 0x2548 && ((*stp1) == 0x0009 || (*stp2) == 0x0009))//연결 시도 data type
        {
            if (*stp1 == 0x0009)
            {
                id = (long long*)(data + 13);
            }
            else if (*stp2 == 0x0009)
            {
                id = (long long*)(data + 14);
            }
            dh->data_messagetype = 9;
            dh->data_userid = *id;
            printf("CASE 67 dh->data_userid: %llx\n", dh->data_userid);
            dh->header_len = 18;
            break;
        }
        else if (dh->data_type == 0x0068) //another client disconnect했을 때 전송되는 패킷. 하지만 유저의 id가 들어있다.
        {
            dh->data_len = 18;
        }
        else if (dh->data_type == 0x01f8) //알 수 없지만 필요없는 값
        {
            dh->data_userid = 0;
        }
        dh->header_len = 18;
        break;
    case 129://ping 0x81
    case 130://pong 0x82
    case 134://acknowledge 0x86
        if (len == 60)
            dh->data_len = 13;//총 길이가 60으로 패딩 됨.
        else if (dh->data_type == 0x6801)
            dh->data_len = 45;//길이가 45로 고정되어있는 경우. 데이터의 내용은 좌표 값이 아니므로 필요없다.
        else
            dh->data_len = dh->data_type / 8; //데이터 길이가 명시되어있지만, lidgren_type이 0x43인 경우와 순서가 다름
        dh->header_len = 5;
        dh->data_type = 0;
        dh->data_messagetype = 0;
        dh->data_userid = 0;
        break;
    case 131: //0x83
    case 132: //0x84
    case 133: //0x85
    case 135: //disconnect 0x87
    case 136: //0x88
    case 137: //0x89
        if (len == 60)
            dh->data_len = 13;//총 길이가 60으로 패딩될 때의 데이터 길이
        else
            dh->data_len = dh->data_type * 2;
        dh->header_len = 5;//0x8*의 데이터는 헤더 길이가 5임
        dh->data_type = 0;
        dh->data_messagetype = 0;
        dh->data_userid = 0;
        break;
    default:
        dh->data_squence = 0;
        dh->data_type = 0;
        dh->data_messagetype = 0;
        dh->data_len = 0;
        dh->header_len = 0;
        printf("default\n");
    }

    return dh;
}


int check_id(struct data_header* dh, long long* user_id_arr, int* current_usr)
{
    int reval = -1;
    if (dh->data_lidgren_type == 67 && dh->data_messagetype == 9 && dh->data_type == 0x2548) //연결시도
    {
        if (dh->data_userid == 0x47219ff680639d65) //서버 userid는 연결받지 않음
            return reval;
        for (int i = 1; i < 5; i++)
        {
            if (user_id_arr[i] == dh->data_userid) //연결하려는 id가 이미 존재한다면, 경고문 출력 및 다음 패킷 받기.
            {
                printf("\n=======!ALREADY REGISTERED!=======\n");
                *current_usr = i;
                return reval;
            }
        }
        for (int i = 1; i < 5; i++)
        {
            if (user_id_arr[i] == 0)//비어있는 배열에 user id 입력. 입력되면 연결로 취급
            {
                printf("\nA CLIENT HAS CONNECTED......\n");
                printf("CHECKID_CLIENT_NUM == %d\n", i);
                user_id_arr[i] = dh->data_userid;
                *current_usr = i;
                reval = 1;
                break;
            }
        }
    }
    else if (dh->data_lidgren_type == 0x87) //연결 종료. 배열에 저장되지 않은 id가 연결 종료 시도할 시에, 경고 문 출력 및 반환 값 수정
    {
        printf("disconnectuser_id_arr: %llx\n", user_id_arr[*current_usr]);
        printf("disconnecti: %d\n", *current_usr);
        printf("\n0x87@@@@@A CLIENT HAS DISCONNECTED......\n");
        reval = 2;
        if (*current_usr == -1)
        {
            printf("!!INVALID DISCONNECTION!!\n");
            reval = 5;
        }
    }
    else if (dh->data_type == 0x0068)
    {
        reval = 4;
    }
    else
    {
        if (dh->data_userid == 0)//dataheader를 확인하는 과정에서 전처리된 데이터. 내용이 필요없는 경우이므로 반환 값만 수정해준다.
        {
            reval = 4;
        }
        else
        {
            for (int i = 1; i < 5; i++) //user_id가 배열에 저장되어 있는가? 를 통해 유효한 패킷인지 확인
            {
                if (dh->data_userid == user_id_arr[i])
                {
                    printf("valid: %d\n", i);
                    *current_usr = i;
                    reval = 3;
                    break;
                }
            }
        }
    }

    return reval;
}


void print_data(const unsigned char* payload, int current_usr)
{
    char temp1[99] = { 0 };
    int x = 0, y = 0;
    char X_Str[10] = "";
    char Y_Str[10] = "";

    sprintf(temp1, "Footprint_Player[%d].txt", current_usr);

    for (int idx = 0; idx < 2; idx++) { // 하위 Byte만 big endian을 따라 string에 저장
        sprintf(X_Str + idx * 2, "%.2x", payload[47 - idx]);
        sprintf(Y_Str + idx * 2, "%.2x", payload[51 - idx]);
    }//정수형으로 변환 하기 위한 문자열로 변환

    x = (int)strtol(X_Str, NULL, 16) - 17208;//정수형으로 변환 뒤 보정
    y = 17781 + (-1 * (int)strtol(Y_Str, NULL, 16));

    if (x <= 0 || y <= 0 || x > 1000 || y > 1000)
        return;

    if (!is_out[current_usr - 1])
    { // 집안에 있을 때
        for (int i = 1; i < current_usr; i++)
            printf("\t\t\t\t");
        printf("Player[%d] in house\n", current_usr);
        // 집안의 y데이터는 334 ~ 501이다.
        if (y < 334)
        { // 집 현관 도착
            past_x[current_usr - 1] = x;
            past_y[current_usr - 1] = y;
            is_out[current_usr - 1] = true; // 이제 외출한다
        }
        return;
    }
    else
    {
        // 이상치 발생(past_x[player_num-1]와 x의 차이가 크면 집에 들어왔다고 판단)
        if (abs(past_x[current_usr - 1] - x) > 400)
        { // 현관에 들어오면 past_x[player_num-1], past_y[player_num-1]값을 다시 바꾼다.
            past_x[current_usr - 1] = 0;
            past_y[current_usr - 1] = 350; //초기값(침대위치)로 변경
            is_out[current_usr - 1] = false; //집으로 갔으니 밖이 아니다.
            return;
        }
        else
        {
            for (int i = 1; i < current_usr; i++)
                printf("\t\t\t\t");

            printf("Player[%d] : (%d, %d)\n", current_usr, x, y);
            past_x[current_usr - 1] = x; //새로운 값으로 이전 데이터 변경
            past_y[current_usr - 1] = y;
            fp[current_usr] = fopen(temp1, "w");//파일 작성
            fprintf(fp[current_usr], "%d %d\n", x, y);
            fclose(fp[current_usr]);
        }
    }
}