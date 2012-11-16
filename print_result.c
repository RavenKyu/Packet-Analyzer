#include "headers.h"

/* Data Link 검출 */
void *print_1_network_connection(DATA_INFO *data_info)
{
    if((data_info -> option & 0x04) != 0x04) /* Summary 모드인지 검사 */
    {
        /* 랜카드 종류를 출력한다. */
        printf("--------[ Level 1 : Network Connection ]---------------------------------------\n");
    }
    
    printf("Network Connection          : ");
    printf("%s\n", data_info -> level_1_network_connection);
    
    return;
}
