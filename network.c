#include <stdio.h>
#include <pcap/pcap.h>          /* man page에서 가리키는 위치가 잘못 적혀 있을 수도 있다. */
#include <net/ethernet.h>       /* 패킷의 구조체를 명시 해 두었다. */

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

	nic_name = pcap_lookupdev(errbuf); /* 장치명을 가져온다. */
	if(nic_name == NULL)                /* 장치명 가쳐오기를 실패할 경우 에러 메세지 처리 후 종료 */
	{
		printf("Failed to get the device name :: %s \n", errbuf);
		return 0;
	}

	nicdev = pcap_open_live(nic_name, 1400, 1, 0, errbuf); /* 장치를 연다 , 장치명, 가져올 패킷 길이, 1로 해주어야 아무 패킷이나 다 받아온다.*/
	if(nicdev == NULL)                                     /* 장치 열기를 실패했을 경우 error 메세지를 출력 후 종료 */
	{
		printf("The device open error :: %s \n", errbuf);

		return 0;
	}

	printf("%s\n", nic_name);

	uc_data = pcap_next(nicdev, &info);

	hex_viewer((unsigned char *)uc_data, 10);

        /* MAC Address를 출력한다. */
        st_Ether = (struc ether_header *)uc_data;
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
        
        /* IP 주소를 출력한다. */
        if(0x45 == *(uc_data + 14)) /* 패킷을 받았을 때만 출력한다. */
        {
            printf("IP  [%d.%d.%d.%d] <- [%d.%d.%d.%d]\n", 
                   *(uc_data + 26),
                   *(uc_data + 27),
                   *(uc_data + 28),
                   *(uc_data + 29),
                   *(uc_data + 30),
                   *(uc_data + 31),
                   *(uc_data + 32),
                   *(uc_data + 34));
        }
        
	pcap_close(nicdev);		
	return 0;
}
