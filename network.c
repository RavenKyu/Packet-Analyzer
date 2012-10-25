#include <stdio.h>
#include <pcap/pcap.h>          /* man page에서 가리키는 위치가 잘못 적혀 있을 수도 있다. */
#include "hex_viewer.h"

char errbuf[PCAP_ERRBUF_SIZE];

int main()
{
	char *nic_name;
	pcap_t *nicdev;         /* 장치 변수 */

	//unsigned char *buff[1400] = {0, }; 
	const unsigned char *uc_data;

	struct pcap_pkthdr info;  

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
	printf("MAC [%02X:%02X:%02X:%02X:%02X:%02X]" 
			" <- [%02X:%02X:%02X:%02X:%02X:%02X] \n", 
               *(uc_data + 0),
               *(uc_data + 1),
               *(uc_data + 2),
               *(uc_data + 3),
               *(uc_data + 4),
               *(uc_data + 5),
               *(uc_data + 6),
               *(uc_data + 7),
               *(uc_data + 8),
               *(uc_data + 9),
               *(uc_data + 10),
               *(uc_data + 11));

	pcap_close(nicdev);		
	return 0;
}
