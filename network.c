#include <stdio.h>
#include <pcap/pcap.h>          /* man page에서 가리키는 위치가 잘못 적혀 있을 수도 있다. */

char errbuf[PCAP_ERRBUF_SIZE];

int main()
{
	char *nic_name;
        pcap_t *nicdev;         /* 장치 변수 */

        nicdev = pcap_open_live(nic_name, 1400, 1, 0, errbuf); /* 장치를 연다 , 장치명, 가져올 패킷 길이, 1로 해주어야 아무 패킷이나 다 받아온다.*/
        if(nicdev == NULL)                                     /* 장치 열기를 실패했을 경우 error 메세지를 출력 후 종료 */
        {
            printf("The device open error :: %s \n", errbuff);

            return 0;
        }
        
	nic_name = pcap_lookupdev(errbuf);
        if(nic_namei = NULL)
        {
            printf("The device :: %s \n", errbuff);
            return 0;
        }
        
	printf("%s\n", nic_name);
        pcap_close(nicdev);		
	return 0;
}
