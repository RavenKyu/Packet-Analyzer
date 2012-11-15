#include "headers.h"

void *level_2_IP(DATA_INFO *ip_port_info)
{
    struct ether_header *st_Ether;
    struct ip *st_ip;
    char *next = NULL;
    
    st_Ether = (struct ether_header *)ip_port_info -> uc_data;
    /* Print IP Version */
    st_ip = (struct ip *)(st_Ether + 1);

    /* 주의해야 할 점.
     * 2바이트 이상의 출력물은 모두 ntohs() 함수를 이용해야 한다.
     * 네트워크 상의 값들은 모두 빅 엔디안 상태에 있다.*/

    if((ip_port_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
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
    }
    
    /* TCP인지 검사 */
    if(ip_port_info -> ip_address != NULL)
    {
        if(st_ip -> ip_p != IPPROTO_TCP)        /* Ethernet이 아닐 경우 */
        {
            printf("Level 3 :: Capturing the packet from the specific IP address is on the \"TCP\" only.\n");

            return (char *)get_packet;
        }
    }

    if((ip_port_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        printf("--------[ Level 3 : Protocol ]------------------------------------------------\n");
    }
    
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

    if((ip_port_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        printf("Checksum                    : %04X\n", ntohs(st_ip -> ip_sum));
    }
    
    /* IP 출력시 주의해야 할 점.
     * IP를 출력시 버퍼가 중복되기 때문에
     * 두번에 걸쳐서 출력을 해 주어야 한다. */
    printf("IP Address                  : [%s] -> ", inet_ntoa(st_ip -> ip_src));
    printf("[%s]\n", inet_ntoa(st_ip -> ip_dst));

    return next;
}
