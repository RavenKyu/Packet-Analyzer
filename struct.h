#ifndef __STRUCT_H__
#define __STRUCT_H__

typedef struct
{
    pcap_t *nicdev;         /* 장치 변수 */
    int datalink;
    
    char *ip_address;           /* 인자로 받은 IP */
    char *port_number;          /* 인자로 받은 Port */
        
    const unsigned char *uc_data;

    unsigned char option;                /* 옵션 */

    /* 출력부 구조 */
    char *level_1_network_connection;
    char level_1_mac_address[11]; /* MAC Address */
    
} DATA_INFO;

#endif  // __STRUCT_H__
