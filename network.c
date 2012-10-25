#include <stdio.h>
#include <pcap/pcap.h>

char errbuf[PCAP_ERRBUF_SIZE];

int main()
{
	char *nic_name;
	nic_name = pcap_lookupdev(errbuf);

	printf("%s\n", nic_name);
			

		
	return 0;
}
