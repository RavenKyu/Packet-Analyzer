#ifndef __STRUCT_H__
#define __STRUCT_H__

typedef struct
{
    char *ip_address;
    char *port_number;
    pcap_t *nicdev;         /* 장치 변수 */
    const unsigned char *uc_data;
    int datalink;
} DATA_INFO;

#endif  // __STRUCT_H__
