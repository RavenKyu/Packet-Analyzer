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
    return;
}
