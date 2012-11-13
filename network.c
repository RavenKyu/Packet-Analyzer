#include <stdio.h>
#include <pcap/pcap.h>          /* man page에서 가리키는 위치가 잘못 적혀 있을 수도 있다. */
#include <net/ethernet.h>       /* 패킷의 구조체를 명시 해 두었다. */
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "hex_viewer.h"

typedef struct
{
    char *ip_address;
    char *port_number;
} IP_PORT_INFO;

char errbuf[PCAP_ERRBUF_SIZE];

pcap_t *dev_open(char *);                 /* 장치를 열고 셋팅하는 함수 */
void *level_1_data_link(int *, const unsigned char **, IP_PORT_INFO *);
void *level_2_IP(int *, const unsigned char **, IP_PORT_INFO *);
void *level_3_tcp(int*, const unsigned char **, IP_PORT_INFO *);
void *level_3_udp(int*, const unsigned char **, IP_PORT_INFO *);

int main(int argc, char *argv[])
{
    pcap_t *nicdev;         /* 장치 변수 */
    int datalink;

    void *(*function)(int *, const unsigned char **, IP_PORT_INFO *);
    
    const unsigned char *uc_data;
    struct pcap_pkthdr info;
    IP_PORT_INFO ip_port = {NULL, NULL};

    /* 인수로 장치명을 받았는지 검사 */
    if(argc == 1)         /* 인자 없이 프로그램이 실행 됐을 시 */
    {
        argv[1] = pcap_lookupdev(errbuf); /* lookup 함수를 통해 최하위 통신 장치로 설정된다. */
    }
    else if(2 < argc || 4 > argc)
    {
        ip_port.ip_address = argv[2];
        ip_port.port_number = argv[3];
    }
    printf("%s %d\n", ip_port.ip_address, atoi(ip_port.port_number));

    
    nicdev = dev_open(argv[1]);        /* 장치를 연다 */

    uc_data = pcap_next(nicdev, &info); /* 패킷을 받아서 해당 구조체 변수에 저장 */
    datalink = pcap_datalink(nicdev);
    
    hex_viewer((unsigned char *)uc_data, 10); /* 헥사뷰로 출력 */
    function = level_1_data_link;
    
    /* 기능 시작 */
    while(1)
    {
        if(function == NULL)
        {
            break;
        }
        function = (*function)(&datalink, &uc_data, &ip_port);
    }

    pcap_close(nicdev);
    
    return 0;    
}

pcap_t *dev_open(char *nic_name)                 /* 장치를 열고 셋팅하는 함수 */
{
    pcap_t *nicdev;         /* 장치 변수 */
    
    /* nic_name = pcap_lookupdev(errbuf); /\* 장치명을 가져온다. *\/ */
    
    if(nic_name == NULL)
    {
        printf("Device Error\n");
        return 0;
    }

    nicdev = pcap_open_live(nic_name, 1400, 1, 0, errbuf); /* 장치를 연다 , 장치 가져올 패킷 길이, 1로 해주어야 아무 패킷이나 다 받아온다.*/
    if(nicdev == NULL)                                     /* 장치 열기를 실패했을 경우 error 메세지를 출력 후 종료 */
    {
        printf("The device open error :: %s \n", errbuf);
            
        return 0;
    }
    
    return nicdev;
}

void *level_1_data_link(int *i_type, const unsigned char **data, IP_PORT_INFO *ip_port_info)
{
    struct ether_header *st_Ether;
    char *next = NULL;

    /* 어떤 모드인지 검사 */
    if(ip_port_info -> ip_address != NULL)
    {
        if(*i_type != 1)        /* Ethernet이 아닐 경우 */
        {
            printf("Level 1 :: Capturing the packet from the specific IP address is on the \"Ethernet\" only.\n");

            return (char *)level_1_data_link;
        }
    }
    
    /* 랜카드 종류를 출력한다. */
    printf("--------[ Level 1 : Network Connection ]---------------------------------------\n");
    printf("Network Connection          : ");
    switch(*i_type)
    {
    case 0:
        printf("no link-layer encapsulation\n");
        *data = 0;
        break;

    case 1:
        printf("Ethernet (10Mb)\n");
        st_Ether = (struct ether_header *)(*data);
        
        break;

    case 2:
        printf("Experimental Ethernet (3Mb)\n");
        break;

    case 3:
        printf("Amateur Radio AX.25\n");
        break;

    case 4:
        printf("Proteon ProNET Token Ring\n");
        break;

    case 5:
        printf("Chaos\n");
        break;

    case 6:
        printf("IEEE 802 Networks\n");
        break;

    case 7:
        printf("ARCNET\n");
        break;

    case 8:
        printf("Serial Line IP\n");
        break;

    case 9:
        printf("Point-to-point Protocol\n");
        break;

    case 10:
        printf("FDDI\n");
        break;
            
    }

    /* MAC Address를 출력한다. */
    printf("MAC Address                 : [%02X:%02X:%02X:%02X:%02X:%02X]" 
           " -> [%02X:%02X:%02X:%02X:%02X:%02X] \n",
           st_Ether -> ether_shost[0], /* 출발지 MAC Address */
           st_Ether -> ether_shost[1],
           st_Ether -> ether_shost[2],
           st_Ether -> ether_shost[3],
           st_Ether -> ether_shost[4],
           st_Ether -> ether_shost[5],
           st_Ether -> ether_dhost[0], /* 목적지 MAC Address */
           st_Ether -> ether_dhost[1],
           st_Ether -> ether_dhost[2],
           st_Ether -> ether_dhost[3],
           st_Ether -> ether_dhost[4],
           st_Ether -> ether_dhost[5]

        );
    
    putchar('\n');

    /* TCP인지 검사 */
    if(ip_port_info -> ip_address != NULL)
    {
        if(ntohs(st_Ether -> ether_type) != ETHERTYPE_IP)        /* Ethernet이 아닐 경우 */
        {
            printf("Level 2 :: Capturing the packet from the specific IP address is on the \"IP\" only.\n");
            
            return (char *)level_1_data_link;
        }
    }
    
    printf("--------[ Level 2 : Network ]--------------------------------------------------\n");

    printf("Network                     : ");
    switch(ntohs(st_Ether -> ether_type))
    {
    case ETHERTYPE_PUP:
        printf("Xerox PUP\n");
        break;
            
    case ETHERTYPE_IP:
        printf("IP\n");
        next = (char *)level_2_IP;
        break;
            
    case ETHERTYPE_ARP:
        printf("Address resolution\n");
        break;
            
    case ETHERTYPE_REVARP:
        printf("Reverse ARP\n");
        break;
            
    default:
        printf("Unknown Type\n");
        /* 패킷의 종류를 출력 */
        /* printf("%04X\n", ntohs(st_Ether -> ether_type)); /\* 호스트 형태로 바꾸겠다. *\/ */
    }
    
    return (char *)next;
}

void *level_2_IP(int* type, const unsigned char **data, IP_PORT_INFO *ip_port_info)
{
    struct ether_header *st_Ether;
    struct ip *st_ip;
    char *next = NULL;
    
    st_Ether = (struct ether_header *)*data;
    /* Print IP Version */
    st_ip = (struct ip *)(st_Ether + 1);

    /* 주의해야 할 점.
     * 2바이트 이상의 출력물은 모두 ntohs() 함수를 이용해야 한다.
     * 네트워크 상의 값들은 모두 빅 엔디안 상태에 있다.*/

    /* IP Header 출력 */
    printf("Version                     : %d\n", st_ip -> ip_v);
    printf("Header length               : %d byte\n", (st_ip -> ip_hl) * 4);
    printf("Type of service             : %02X\n", st_ip -> ip_tos);
    printf("Total length                : %d\n", ntohs(st_ip -> ip_len));
    printf("Identification              : %d(%04X)\n", ntohs(st_ip -> ip_id), ntohs(st_ip -> ip_id));

    printf("Flagment offset filed       : %d\n", (ntohs(st_ip -> ip_off) & IP_OFFMASK));
    printf("Reserved bit                : %s\n", ((ntohs(st_ip -> ip_off) & IP_RF) == IP_RF) ? "Set" : "Not set");
    printf("Don't fragment bit          : %s\n", ((ntohs(st_ip -> ip_off) & IP_DF) == IP_DF) ? "Set" : "Not set");
    printf("More fragment bit           : %s\n", ((ntohs(st_ip -> ip_off) & IP_MF) == IP_MF) ? "Set" : "Not set");

    printf("Time to live                : %d\n", st_ip -> ip_ttl);
    
    putchar('\n');

    /* TCP인지 검사 */
    if(ip_port_info -> ip_address != NULL)
    {
        if(st_ip -> ip_p != IPPROTO_TCP)        /* Ethernet이 아닐 경우 */
        {
            printf("Level 3 :: Capturing the packet from the specific IP address is on the \"TCP\" only.\n");

            return (char *)level_1_data_link;
        }
    }
    
    printf("--------[ Level 3 : Protocol ]------------------------------------------------\n");    
    printf("Protocol                    : ");
    
    switch(st_ip -> ip_p)
    {
    case IPPROTO_IP:
        printf("Dummy protocol for TCP.n");
        break;

    case IPPROTO_ICMP :
	printf("Internet Control Message Protocol.\n");
	break;
    
    case IPPROTO_IGMP :
	printf("Internet Group Management Protocol\n");
	break;
    
    case IPPROTO_IPIP :
	printf("IPIP tunnels (older KA9Q tunnels use 94).\n");
	break;
    
    case IPPROTO_TCP :
	printf("Transmission Control Protocol.\n");
        next = (char *)level_3_tcp;
	break;
    
    case IPPROTO_EGP :
	printf("Exterior Gateway Protocol.\n");
	break;
    
    case IPPROTO_PUP :
	printf("PUP protocol.\n");
	break;
    
    case IPPROTO_UDP :
	printf("User Datagram Protocol.\n");
        next = (char *)level_3_udp;
	break;
    
    case IPPROTO_IDP :
	printf("XNS IDP protocol.\n");
	break;
    
    case IPPROTO_TP :
	printf("SO Transport Protocol Class 4.\n");
	break;
    
    case IPPROTO_RAW :
	printf("Raw IP packets.\n");
	break;
    
    default:
        printf("\n");
        break;
    }

    printf("Checksum                    : %04X\n", ntohs(st_ip -> ip_sum));

    /* IP 출력시 주의해야 할 점.
     * IP를 출력시 버퍼가 중복되기 때문에
     * 두번에 걸쳐서 출력을 해 주어야 한다. */
    printf("IP Address                  : [%s] -> ", inet_ntoa(st_ip -> ip_src));
    printf("[%s]\n", inet_ntoa(st_ip -> ip_dst));

    return next;
}

void *level_3_tcp(int *not_use, const unsigned char **tcp_info, IP_PORT_INFO *ip_port_info)
{
    struct tcphdr *tcp_header;

    tcp_header = (struct tcphdr *)(*tcp_info + 34);

    printf("Source Port                 : %d\n", ntohs(tcp_header -> source));
    printf("Destination Port            : %d\n", ntohs(tcp_header -> dest));
    printf("Seq                         : %d\n", ntohs(tcp_header -> seq));
    printf("Ack                         : %d\n", ntohs(tcp_header -> ack_seq));
    putchar('\n');
    return 0;
}

void *level_3_udp(int *not_use, const unsigned char **udp_info, IP_PORT_INFO *IP_not_use)
{
    struct udphdr *udp_header;

    udp_header = (struct udphdr *)(*udp_info + 34);

    printf("Source Port : %d\n", ntohs(udp_header -> source));
    printf("Destination Port : %d\n", ntohs(udp_header -> dest));
    printf("Len : %d\n", ntohs(udp_header -> len));
    printf("Check : %d\n", ntohs(udp_header -> check));
    
    return 0;
}
