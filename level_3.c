#include "headers.h"

void *level_3_tcp(DATA_INFO *data_info)
{
    struct tcphdr *tcp_header;

    tcp_header = (struct tcphdr *)(data_info -> uc_data + 34);

    printf("Source Port                 : %d\n", ntohs(tcp_header -> source));
    printf("Destination Port            : %d\n", ntohs(tcp_header -> dest));
    printf("Seq                         : %d\n", ntohs(tcp_header -> seq));
    printf("Ack                         : %d\n", ntohs(tcp_header -> ack_seq));
    putchar('\n');
    return 0;
}

void *level_3_udp(DATA_INFO *data_info)
{
    struct udphdr *udp_header;

    udp_header = (struct udphdr *)(data_info -> uc_data + 34);

    printf("Source Port : %d\n", ntohs(udp_header -> source));
    printf("Destination Port : %d\n", ntohs(udp_header -> dest));
    printf("Len : %d\n", ntohs(udp_header -> len));
    printf("Check : %d\n", ntohs(udp_header -> check));
    
    return 0;
}
