#include "headers.h"

int main(int argc, char *argv[])
{
    void *(*function)(DATA_INFO *);
    
    DATA_INFO data_info = {NULL, };

    /* 프로그램 실행시 받은 인자를 검사. */
    check_arguments(argc, argv, &data_info);

    /* 장치를 연다 */
    data_info.nicdev = dev_open(argv[1]);
    function = get_packet;
    
    /* 기능 시작 */
    while(1)
    {
        if(function == NULL)
        {
            break;
        }
        function = (*function)(&data_info);
    }

    pcap_close(data_info.nicdev);
    
    return 0;    
}
