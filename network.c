#include <stdio.h>
#include <pcap/pcap.h>          /* man page에서 가리키는 위치가 잘못 적혀 있을 수도 있다. */
#include <net/ethernet.h>       /* 패킷의 구조체를 명시 해 두었다. */
#include <netinet/ip.h>

#include "hex_viewer.h"

char errbuf[PCAP_ERRBUF_SIZE];

int main()
{
    char *nic_name;
    pcap_t *nicdev;         /* 장치 변수 */

    //unsigned char *buff[1400] = {0, }; 
    const unsigned char *uc_data;

    struct pcap_pkthdr info;
    struct ether_header *st_Ether;
    struct ip *st_ip;

    nic_name = pcap_lookupdev(errbuf); /* 장치명을 가져온다. */
    if(nic_name == NULL)                
    {
        printf("Device Error\n");
        return 0;
    }

    nicdev = pcap_open_live(nic_name, 1400, 1, 0, errbuf); /* 장치를 연다 , 장치 가져올 패킷 길이, 1로 해주어야 아무 패킷이나 다 받아온다.*/
    /* nicdev = pcap_open_live("eth1", 1400, 1, 0, errbuf); /\* 장치를 연다 , 장치 가져올 패킷 길이, 1로 해주어야 아무 패킷이나 다 받아온다.*\/ */
    if(nicdev == NULL)                                     /* 장치 열기를 실패했을 경우 error 메세지를 출력 후 종료 */
    {
        printf("The device open error :: %s \n", errbuf);
            
        return 0;
    }

    printf("%s\n", nic_name);

    uc_data = pcap_next(nicdev, &info);

    hex_viewer((unsigned char *)uc_data, 10);

    /* 랜카드 종류를 출력한다. */
    switch(pcap_datalink(nicdev))
    {
    case 0:
        printf("no link-layer encapsulation\n");
        break;
                                
    case 1:
        printf("Ethernet (10Mb)\n");
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

    st_Ether = (struct ether_header *)uc_data;

    /* MAC Address를 출력한다. */
    printf("MAC [%02X:%02X:%02X:%02X:%02X:%02X]" 
           " <- [%02X:%02X:%02X:%02X:%02X:%02X] \n", 
           st_Ether -> ether_dhost[0], /* 목적지 MAC Address */
           st_Ether -> ether_dhost[1],
           st_Ether -> ether_dhost[2],
           st_Ether -> ether_dhost[3],
           st_Ether -> ether_dhost[4],
           st_Ether -> ether_dhost[5],
           st_Ether -> ether_shost[0], /* 출발지 MAC Address */
           st_Ether -> ether_shost[1],
           st_Ether -> ether_shost[2],
           st_Ether -> ether_shost[3],
           st_Ether -> ether_shost[4],
           st_Ether -> ether_shost[5]
        );
        
    switch(ntohs(st_Ether -> ether_type))
    {
    case ETHERTYPE_PUP:
        printf("Xerox PUP\n");
        break;
            
    case ETHERTYPE_IP:
        printf("IP\n");
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

    /* Print IP Version */
    st_ip = (struct ip *)(st_Ether + 1);

    /* 주의해야 할 점.
     * 2바이트 이상의 출력물은 모두 ntohs() 함수를 이용해야 한다.
     * 네트워크 상의 값들은 모두 빅 엔디안 상태에 있다.*/

    /* IP Header 출력 */
    printf("Version : %d\n", st_ip -> ip_v);
    printf("Header length : %d byte\n", (st_ip -> ip_hl) * 4);
    printf("Type of service : %02X\n", st_ip -> ip_tos);
    printf("Total length : %d\n", ntohs(st_ip -> ip_len));
    printf("Identification : %d(%04X)\n", ntohs(st_ip -> ip_id), ntohs(st_ip -> ip_id));

    printf("Flagment offset filed : %d\n", (ntohs(st_ip -> ip_off) & IP_OFFMASK));
    printf("Reserved bit : %s\n", ((ntohs(st_ip -> ip_off) & IP_RF) == IP_RF) ? "Set" : "Not set");
    printf("Don't fragment bit : %s\n", ((ntohs(st_ip -> ip_off) & IP_DF) == IP_DF) ? "Set" : "Not set");
    printf("More fragment bit : %s\n", ((ntohs(st_ip -> ip_off) & IP_MF) == IP_MF) ? "Set" : "Not set");

    printf("Time to live : %d\n", st_ip -> ip_ttl);
    printf("Protocol : %d\n", st_ip -> ip_p);
    printf("Checksum : %04X\n", ntohs(st_ip -> ip_sum));

    /* IP 출력시 주의해야 할 점.
     * IP를 출력시 버퍼가 중복되기 때문에
     * 두번에 걸쳐서 출력을 해 주어야 한다. */
    printf("IP [%s] -> ", inet_ntoa(st_ip -> ip_src));
    printf("[%s]\n", inet_ntoa(st_ip -> ip_dst));
    
    pcap_close(nicdev);		
    return 0;
}
