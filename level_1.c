#include "headers.h"

void *level_1_data_link(DATA_INFO *data_info)
{
    struct ether_header *st_Ether;
    char *next = NULL;
    int i;
    char buffer[20] = "";

    /* 어떤 모드인지 검사 */
    if(data_info -> ip_address != NULL)
    {
        if(data_info -> datalink != 1)        /* Ethernet이 아닐 경우 */
        {
            return (char *)get_packet; /* 패킷을 다시 받으러 간다. */
        }
    }

    /* Datalink를 검출 */
    switch(data_info -> datalink)
    {
    case 0:
        data_info -> level_1_network_connection = "no link-layer encapsulation";
        break;

    case 1:
        data_info -> level_1_network_connection = "Ethernet (10Mb)";
        st_Ether = (struct ether_header *)data_info -> uc_data;
        break;

    case 2:
        data_info -> level_1_network_connection = "Experimental Ethernet (3Mb)";
        break;

    case 3:
        data_info -> level_1_network_connection = "Amateur Radio AX.25";
        break;

    case 4:
        data_info -> level_1_network_connection = "Proteon ProNET Token Ring";
        break;

    case 5:
        data_info -> level_1_network_connection = "Chaos";
        break;

    case 6:
        data_info -> level_1_network_connection = "IEEE 802 Networks";
        break;

    case 7:
        data_info -> level_1_network_connection = "ARCNET";
        break;

    case 8:
        data_info -> level_1_network_connection = "Serial Line IP";
        break;

    case 9:
        data_info -> level_1_network_connection = "Point-to-point Protocol";
        break;

    case 10:
        data_info -> level_1_network_connection = "FDDI";
        break;
            
    }

    /* MAC Address 를 검출
     * 추출한 값을 배열에 출발지, 도착지 차례로 넣는다. */
    for(i = 0; 11 >= i; i++)
    {
        if(6 > i)               /* 출발지 MAC Address */
        {
            data_info -> level_1_mac_address[i] = st_Ether -> ether_shost[i];
        }
        else                    /* 도착지 MAC Address */
        {
            data_info -> level_1_mac_address[i] = st_Ether -> ether_dhost[i - 5];
        }
    }
    
    /* TCP인지 검사 */
    if(data_info -> ip_address != NULL)
    {
        if(ntohs(st_Ether -> ether_type) != ETHERTYPE_IP)        /* Ethernet이 아닐 경우 */
        {
            return (char *)get_packet;
        }
    }
    
    switch(ntohs(st_Ether -> ether_type))
    {
    case ETHERTYPE_PUP:
        data_info -> level_2_network_layer = "Xerox PUP";
        break;
            
    case ETHERTYPE_IP:
        data_info -> level_2_network_layer = "IP";
        next = (char *)level_2_IP;
        break;
            
    case ETHERTYPE_ARP:
        data_info -> level_2_network_layer = "Address resolution";
        break;
            
    case ETHERTYPE_REVARP:
        data_info -> level_2_network_layer = "Reverse ARP";
        break;
            
    default:
        data_info -> level_2_network_layer = "Unknown Type";
    }
    
    return (char *)next;
}
