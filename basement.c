#include "headers.h"

static char errbuf[PCAP_ERRBUF_SIZE];

void check_arguments(int argc, char *argv[], DATA_INFO *data_info)
{
    /* 인수로 장치명을 받았는지 검사 */
    if(argc == 1)         /* 인자 없이 프로그램이 실행 됐을 시 */
    {
        argv[1] = pcap_lookupdev(errbuf); /* lookupdev 함수를 통해 최하위 통신 장치로 설정된다. */
    }
    else if(2 < argc || 4 > argc) /* 인자로 IP Address와 Port를 받았을 경우 */
    {
        data_info -> ip_address = argv[2];
        data_info -> port_number = argv[3];
    }

    return;
}

pcap_t *dev_open(char *nic_name)                 /* 장치를 열고 셋팅하는 함수 */
{
    pcap_t *nicdev;         /* 장치 변수 */
    
    /* nic_name = pcap_lookupdev(errbuf); /\* 장치명을 가져온다. *\/ */
    
    if(nic_name == NULL)
    {
        printf("Device Error\n");
        return 0;
    }

    nicdev = pcap_open_live(nic_name, 1400, 1, 0, errbuf); /* 장치를 연다 , 장치 가져올 패킷 길이, 1로 해주어야 아무 패킷이나 다 받아온다.*/
    if(nicdev == NULL)                                     /* 장치 열기를 실패했을 경우 error 메세지를 출력 후 종료 */
    {
        printf("The device open error :: %s \n", errbuf);
            
        return 0;
    }
    
    return nicdev;
}

void *get_packet(DATA_INFO *data_info)
{
    struct pcap_pkthdr info;
                                
    data_info -> uc_data = pcap_next(data_info -> nicdev, &info); /* 패킷을 받아서 해당 구조체 변수에 저장 */
    data_info -> datalink = pcap_datalink(data_info -> nicdev);

    hex_viewer((unsigned char *)data_info -> uc_data, 10); /* 헥사뷰로 출력 */
    
    return (char *)level_1_data_link;
}