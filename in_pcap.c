#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>

#include <pcap.h>

#include "params.h"
#include "in.h"

static pcap_t *p;

int in_init(void)
{
	char *device;
	char error[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;

#ifdef SCANLOGD_DEVICE
	device = SCANLOGD_DEVICE;
#else
	if (!(device = pcap_lookupdev(error))) {
		fprintf(stderr, "pcap_lookupdev: %s\n", error);
		return 1;
	}
#endif

	if (!(p = pcap_open_live(device, sizeof(struct header),
	    SCANLOGD_PROMISC, 0, error))) {
		fprintf(stderr, "pcap_open_live: %s\n", error);
		return 1;
	}

	if (pcap_compile(p, &filter, SCANLOGD_PCAP_FILTER, 1, PCAP_NETMASK_UNKNOWN)) {
		pcap_perror(p, "pcap_compile");
		return 1;
	}

	if (pcap_setfilter(p, &filter)) {
		pcap_perror(p, "pcap_setfilter");
		return 1;
	}

	return 0;
}

void in_run(void (*process_packet)(struct header *packet, int size))
{
	int hw_size, size;
	const u_char *packet_data;
	struct pcap_pkthdr *header;

	switch (pcap_datalink(p)) {
	case DLT_RAW:
	case DLT_SLIP:
		hw_size = 0;
		break;

	case DLT_PPP:
		hw_size = 4;
		break;

	case DLT_EN10MB:
	default:
		hw_size = 14;
		break;
	}

	if(SCANLOGD_DEVICE == NULL || strcmp(SCANLOGD_DEVICE, "any") == 0)
		hw_size += 2;
	
	int next_ret = 0;
	while (1) {
		next_ret = pcap_next_ex(p, &header, &packet_data);
		if(next_ret == 0) continue;
		if(next_ret != 1) {
			fprintf(stderr, "pcap_next_ex error: %d", next_ret);
			break;
		}

		packet_data += hw_size;
		size = header->caplen - hw_size;
		
		if(size <= 0) continue;

		process_packet((struct header *)packet_data, size);
	}
}
