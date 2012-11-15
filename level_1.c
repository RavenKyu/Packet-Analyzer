#include "headers.h"

void *level_1_data_link(DATA_INFO *data_info)
{
    struct ether_header *st_Ether;
    char *next = NULL;

    /* 어떤 모드인지 검사 */
    if(data_info -> ip_address != NULL)
    {
        if(data_info -> datalink != 1)        /* Ethernet이 아닐 경우 */
        {
            printf("Level 1 :: Capturing the packet from the specific IP address is on the \"Ethernet\" only.\n");

            return (char *)get_packet;
        }
    }

    if((data_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        /* 랜카드 종류를 출력한다. */
        printf("--------[ Level 1 : Network Connection ]---------------------------------------\n");
    }
    
    printf("Network Connection          : ");
    switch(data_info -> datalink)
    {
    case 0:
        printf("no link-layer encapsulation\n");
        break;

    case 1:
        printf("Ethernet (10Mb)\n");
        st_Ether = (struct ether_header *)data_info -> uc_data;
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

    if((data_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */     
    {
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
    }
    
    /* TCP인지 검사 */
    if(data_info -> ip_address != NULL)
    {
        if(ntohs(st_Ether -> ether_type) != ETHERTYPE_IP)        /* Ethernet이 아닐 경우 */
        {
            printf("Level 2 :: Capturing the packet from the specific IP address is on the \"IP\" only.\n");
            
            return (char *)get_packet;
        }
    }

    if((data_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        printf("--------[ Level 2 : Network ]--------------------------------------------------\n");
    }
    
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
