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

    char *level_2_network_layer;
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
    u_int8_t ip_tos;			/* type of service */
    u_short ip_len;			/* total length */
    u_short ip_id;			/* identification */
    u_short ip_off;			/* fragment offset field */
    u_int8_t ip_ttl;			/* time to live */
    u_int8_t ip_p;			/* protocol */
    u_short ip_sum;			/* checksum */

    char *level_3_ipproto;
    struct in_addr ip_src, ip_dst;	/* source and dest address */
    
} DATA_INFO;

#endif  // __STRUCT_H__
