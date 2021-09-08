#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include <PcapLiveDeviceList.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>

extern "C" {
#include "params.h"
#include "in.h"
}

static pcpp::PcapLiveDevice* captureDev;
static int hw_size = 16;
static void (*static_process_packet_ipv4)(struct header *packet, int size);
static void (*static_process_packet_ipv6)(struct ip6_hdr *header, uint8_t* tcp_header, int size);

int in_init(void)
{
	const char *device;
	static_process_packet_ipv4 = NULL;
	static_process_packet_ipv6 = NULL;
#ifdef SCANLOGD_DEVICE
	device = SCANLOGD_DEVICE;
#else
	device = "any";
#endif
	debug_printf("pcpp device: %s\n",device);
	std::string str_device(device);
	captureDev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(str_device);

	if(captureDev == NULL) {
	        fprintf(stderr, "pcpp: device lookup failed\n");
                return 1;
	}

	debug_printf("pcpp device: %s %s\n", captureDev->getName().c_str(), captureDev->getIPv4Address().toString().c_str());
/* TODO
	if (pcap_compile(p, &filter, SCANLOGD_PCAP_FILTER, 1, PCAP_NETMASK_UNKNOWN)) {
		pcap_perror(p, "pcap_compile");
		return 1;
	}

	if (pcap_setfilter(p, &filter)) {
		pcap_perror(p, "pcap_setfilter");
		return 1;
	}
*/
	return 0;
}

static bool onPacketArrivesBlockingMode(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
//	pcpp::Packet parsedPacket(packet);
	
	const uint8_t *packet_data = packet->getRawData();
	int size = packet->getRawDataLen();

	packet_data += hw_size;
        size -= hw_size;
                
        if(size <= 0 || size < (int) sizeof(struct ip)) return false;

        struct ip *ip_header = (struct ip*) packet_data;

        if(ip_header->ip_v == 4) {
		if(static_process_packet_ipv4) {
			static_process_packet_ipv4((struct header *)packet_data, size);
		}
	} else if(ip_header->ip_v == 6) {
		if(static_process_packet_ipv6) {
			pcpp::Packet parsedPacket(packet);
			ip6_hdr hdr = *(ip6_hdr*)(parsedPacket.getLayerOfType(pcpp::IPv6)->getData());
			pcpp::TcpLayer *tcp = (pcpp::TcpLayer*)parsedPacket.getLayerOfType(pcpp::TCP);
			static_process_packet_ipv6(&hdr, tcp->getData(), (int)tcp->getDataLen());
		}
	}

	return false;
}

void in_run(void (*process_packet_ipv4)(struct header *packet, int size),
	void (*process_packet_ipv6)(struct ip6_hdr *header, uint8_t* tcp_header, int size))
{
#if 0
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
		
		if(size <= 0 || size < sizeof(struct ip)) continue;

		struct ip *ip_header = (struct ip*) packet_data;

		if(ip_header->ip_v == 4)
			process_packet((struct header *)packet_data, size);
	}
#endif
        if (!captureDev->open()) {
                fprintf(stderr, "pcpp: device open failed\n");
                return;
        }


	std::string str_filter(SCANLOGD_PCAP_FILTER);
	if(!captureDev->setFilter(str_filter))
	{
		fprintf(stderr, "pccp: set filter failed: %s\n", SCANLOGD_PCAP_FILTER);
		return;
	}

	static_process_packet_ipv4 = process_packet_ipv4;
        static_process_packet_ipv6 = process_packet_ipv6;

	int ret = captureDev->startCaptureBlockingMode(onPacketArrivesBlockingMode, NULL, 0); 
	if(ret == 0) {
        	fprintf(stderr, "pcpp: startCaptureBlockingMode eror");
                return;
	}
}
