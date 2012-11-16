#include "headers.h"

void *level_2_IP(DATA_INFO *ip_port_info)
{
    struct ether_header *st_Ether;
    struct ip *st_ip;
    char *next = NULL;
    
    st_Ether = (struct ether_header *)ip_port_info -> uc_data;
    /* Print IP Version */
    st_ip = (struct ip *)(st_Ether + 1);

    /* IP Header 출력*/
    if((ip_port_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        /* IP Header 출력 */
        ip_port_info -> ip_v = st_ip -> ip_v;
        ip_port_info -> ip_hl = st_ip -> ip_hl;
        ip_port_info -> ip_tos = st_ip -> ip_tos;
        ip_port_info -> ip_len = st_ip -> ip_len;
        ip_port_info -> ip_id =  st_ip -> ip_id;
        ip_port_info -> ip_off =  st_ip -> ip_off;
        ip_port_info -> ip_ttl =  st_ip -> ip_ttl;
    }

    if((ip_port_info -> option & 0x01) == 0x01) /* TCP 모드인지 검사 */
    {
        /* TCP인지 검사 */
        if(ip_port_info -> ip_address != NULL)
        {
            if(st_ip -> ip_p != IPPROTO_TCP)        /* Ethernet이 아닐 경우 */
            {
                return (char *)get_packet;
            }
        }
    }

    if((ip_port_info -> option & 0x02) == 0x02) /* UDP 모드인지 검사 */
    {
        /* UDP인지 검사 */
        if(ip_port_info -> ip_address != NULL)
        {
            if(st_ip -> ip_p != IPPROTO_UDP)        /* Ethernet이 아닐 경우 */
            {
                return (char *)get_packet;
            }
        }
    }

    switch(st_ip -> ip_p)
    {
    case IPPROTO_IP:
        ip_port_info -> level_3_ipproto = "Dummy protocol for TCP.";
        break;

    case IPPROTO_ICMP :
        ip_port_info -> level_3_ipproto = "Internet Control Message Protocol.";
	break;
    
    case IPPROTO_IGMP :
	ip_port_info -> level_3_ipproto = "Internet Group Management Protocol";
	break;
    
    case IPPROTO_IPIP :
        ip_port_info -> level_3_ipproto = "IPIP tunnels (older KA9Q tunnels use 94.";
	break;
    
    case IPPROTO_TCP :
        ip_port_info -> level_3_ipproto = "Transmission Control Protocol.";
        next = (char *)level_3_tcp;
	break;
    
    case IPPROTO_EGP :
        ip_port_info -> level_3_ipproto = "Exterior Gateway Protocol.";
	break;
    
    case IPPROTO_PUP :
        ip_port_info -> level_3_ipproto = "PUP protocol.";
	break;
    
    case IPPROTO_UDP :
        ip_port_info -> level_3_ipproto = "User Datagram Protocol.";
        next = (char *)level_3_udp;
	break;
    
    case IPPROTO_IDP :
        ip_port_info -> level_3_ipproto = "XNS IDP protocol.";
	break;
    
    case IPPROTO_TP :
        ip_port_info -> level_3_ipproto = "SO Transport Protocol Class 4.";
	break;
    
    case IPPROTO_RAW :
        ip_port_info -> level_3_ipproto = "Raw IP packets.";
	break;
    
    default:
        ip_port_info -> level_3_ipproto = "";
        break;
    }

    if((ip_port_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        ip_port_info -> ip_sum = st_ip -> ip_sum;
    }
    
    /* IP 출력시 주의해야 할 점.
     * IP를 출력시 버퍼가 중복되기 때문에
     * 두번에 걸쳐서 출력을 해 주어야 한다. */
    ip_port_info -> ip_src = st_ip -> ip_src;
    ip_port_info -> ip_dst = st_ip -> ip_dst;

    return next;
}
