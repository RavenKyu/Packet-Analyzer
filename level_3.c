#include "headers.h"

void *level_3_tcp(DATA_INFO *data_info)
{
    struct tcphdr *tcp_header;

    tcp_header = (struct tcphdr *)(data_info -> uc_data + 34);

    data_info -> source = tcp_header -> source;
    data_info -> dest = tcp_header -> dest; /* Destination Port */
    data_info -> seq = tcp_header -> seq; /* Seq */
    data_info -> ack_seq = tcp_header -> ack_seq; /* Ack */

    return 0;
}

void *level_3_udp(DATA_INFO *data_info)
{
    struct udphdr *udp_header;

    udp_header = (struct udphdr *)(data_info -> uc_data + 34);

    data_info -> source = udp_header -> source;
    data_info -> dest = udp_header -> dest; /* Destination Port */
    data_info -> len = udp_header -> len; /* len */
    data_info -> check = udp_header -> check; /* check */
    
    return 0;
}
