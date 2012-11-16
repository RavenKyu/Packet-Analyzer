#include "headers.h"

void *print_1_network_connection(DATA_INFO *data_info)
{
    int i;
    
    if((data_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        /* 랜카드 종류를 출력한다. */
        printf("--------[ Level 1 : Network Connection ]---------------------------------------\n");
    }
    
    printf("Network Connection          : ");
    printf("%s\n", data_info -> level_1_network_connection);

    if((data_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */     
    {
    /* MAC Address를 출력한다.
     * 출발지와 도착지의 값은 배열 한 개에 차례대로 들어가 있다*/
        printf("MAC Address                 : ");

        printf("[");
        for(i = 0; 11 >= i; i++)
        {
            printf("%02X", (unsigned char)data_info -> level_1_mac_address[i]);
            if(5 != i && 11 != i)
            {
                printf(":");
            }
            else if(5 == i)
            {
                printf("] -> [");
            }
            else if(11 == i)
            {
                printf("]\n");
            }
        }
    }

    /* Level 2 */
    if((data_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        printf("--------[ Level 2 : Network ]--------------------------------------------------\n");
    }
    printf("Network                     : ");
    printf("%s\n", data_info -> level_2_network_layer);

    /* 주의해야 할 점.
     * 2바이트 이상의 출력물은 모두 ntohs() 함수를 이용해야 한다.
     * 네트워크 상의 값들은 모두 빅 엔디안 상태에 있다.*/

    if((data_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        /* IP Header 출력 */
        printf("Version                     : %d\n", data_info -> ip_v);
        printf("Header length               : %d byte\n", (data_info -> ip_hl) * 4);
        printf("Type of service             : %02X\n", data_info -> ip_tos);
        printf("Total length                : %d\n", ntohs(data_info -> ip_len));
        printf("Identification              : %d(%04X)\n", ntohs(data_info -> ip_id), ntohs(data_info -> ip_id));

        printf("Flagment offset filed       : %d\n", (ntohs(data_info -> ip_off) & IP_OFFMASK));
        printf("Reserved bit                : %s\n", ((ntohs(data_info -> ip_off) & IP_RF) == IP_RF) ? "Set" : "Not set");
        printf("Don't fragment bit          : %s\n", ((ntohs(data_info -> ip_off) & IP_DF) == IP_DF) ? "Set" : "Not set");
        printf("More fragment bit           : %s\n", ((ntohs(data_info -> ip_off) & IP_MF) == IP_MF) ? "Set" : "Not set");

        printf("Time to live                : %d\n", data_info -> ip_ttl);
    }

    /* Transport 출력 */
    if((data_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        printf("--------[ Level 3 : Protocol ]------------------------------------------------\n");
    }
    
    printf("Protocol                    : ");
    printf("%s\n", data_info -> level_3_ipproto);

    if((data_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        printf("Checksum                    : %04X\n", ntohs(data_info -> ip_sum));
    }

    printf("IP Address                  : [%s] -> ", inet_ntoa(data_info -> ip_src));
    printf("[%s]\n", inet_ntoa(data_info -> ip_dst));
    
    return;
}
