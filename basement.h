#ifndef __BASEMENT_H__
#define __BASEMENT_H__

extern void check_arguments(int, char *[], DATA_INFO *); /* 인자를 받았는지 검사하는 함수 */
extern pcap_t *dev_open(char *);                 /* 장치를 열고 셋팅하는 함수 */
extern void *get_packet(DATA_INFO *);

#endif // __BASEMENT_H__
