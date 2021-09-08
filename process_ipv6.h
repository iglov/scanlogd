#include "hash.h"

void process_ipv6_init();
void process_packet_ipv6(struct ip6_hdr *header, uint8_t *tcp_header, int size);

