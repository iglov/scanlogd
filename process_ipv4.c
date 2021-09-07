/*
 * Copyright (c) 1998-2012 by Solar Designer
 * See LICENSE
 */

#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>
#include <sys/times.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "params.h"
#include "main.h"
#include "in.h"
#include "hash.h"

#define HF_DADDR_CHANGING		0x01
#define HF_SPORT_CHANGING		0x02
#define HF_TOS_CHANGING			0x04
#define HF_TTL_CHANGING			0x08

static struct hash_table *table_ipv4;

/*
 * Information we keep per each source address.
 */
struct host_ipv4 {
	clock_t timestamp;		/* Last update time */
	time_t start;			/* Entry creation time */
	struct in_addr saddr, daddr;	/* Source and destination addresses */
	unsigned short sport;		/* Source port */
	int count;			/* Number of ports in the list */
	int weight;			/* Total weight of ports in the list */
	unsigned short ports[SCAN_MAX_COUNT - 1];	/* List of ports */
	unsigned char tos;		/* TOS */
	unsigned char ttl;		/* TTL */
	unsigned char flags_or;		/* TCP flags OR mask */
	unsigned char flags_and;	/* TCP flags AND mask */
	unsigned char flags;		/* HF_ flags bitmask */
};

void process_ipv4_init()
{
	table_ipv4 = hash_create_table(sizeof(struct in_addr), sizeof(struct host_ipv4));
}

/*
 * Log this port scan.
 */
static void do_log(struct host_ipv4 *info)
{
	int limit;
	char s_saddr[32];
	char s_daddr[64 + 8 * SCAN_MAX_COUNT];
	char s_flags[16];
	char s_tos[16];
	char s_ttl[16];
	char s_time[32];
	int index, size;
	unsigned char mask;

/* We try to log everything we can at first, then remove port numbers one
 * by one if necessary until we fit into the maximum allowed length */
	limit = info->count;
prepare:

/* Source address and port number, if fixed */
	snprintf(s_saddr, sizeof(s_saddr),
		(info->flags & HF_SPORT_CHANGING) ? "%s" : "%s:%u",
		inet_ntoa(info->saddr),
		(unsigned int)ntohs(info->sport));

/* Destination address */
	snprintf(s_daddr, sizeof(s_daddr), "%s%s ports ",
		inet_ntoa(info->daddr),
		(info->flags & HF_DADDR_CHANGING) ? " and others," : "");

/* Scanned port numbers */
	for (index = 0; index < limit; index++) {
		size = strlen(s_daddr);
#ifdef LOG_MAX_LENGTH
		if (size >= LOG_MAX_LENGTH) {
			limit = index;
			break;
		}
#endif
		snprintf(s_daddr + size, sizeof(s_daddr) - size,
			"%u, ", (unsigned int)ntohs(info->ports[index]));
	}

/* TCP flags: lowercase letters for "always clear", uppercase for "always
 * set", and question marks for "sometimes set". */
	for (index = 0; index < 8; index++) {
		mask = 1 << index;
		if ((info->flags_or & mask) == (info->flags_and & mask)) {
			s_flags[index] = "fsrpauxy"[index];
			if (info->flags_or & mask)
				s_flags[index] =
				    toupper((int)(unsigned char)s_flags[index]);
		} else
			s_flags[index] = '?';
	}
	s_flags[index] = 0;

/* TOS, if fixed */
	snprintf(s_tos, sizeof(s_tos),
		(info->flags & HF_TOS_CHANGING) ? "" : ", TOS %02x",
		(unsigned int)info->tos);

/* TTL, if fixed */
	snprintf(s_ttl, sizeof(s_ttl),
		(info->flags & HF_TTL_CHANGING) ? "" : ", TTL %u",
		(unsigned int)info->ttl);

/* Scan start time */
	strftime(s_time, sizeof(s_time), "%X", localtime(&info->start));

/* Check against the length limit, and possibly re-format everything */
#ifdef LOG_MAX_LENGTH
	if (strlen(s_saddr) + strlen(s_daddr) +
	    strlen(s_tos) + strlen(s_ttl) + strlen(s_time) +
	    (4 + 5 + 8 + 2) > LOG_MAX_LENGTH) {
		if (--limit > 0) goto prepare;
	}
#endif

/* Log it all */
	syslog(SYSLOG_LEVEL,
		"%s to %s..., %s%s%s @%s",
		s_saddr, s_daddr, s_flags, s_tos, s_ttl, s_time);
}

/*
 * Log this port scan unless we're being flooded.
 */
static void safe_log(struct host_ipv4 *info)
{
	static clock_t last = 0;
	static int count = 0;
	clock_t now;

	now = info->timestamp;
	if (now - last > log_delay_threshold || now < last) count = 0;
	if (++count <= LOG_COUNT_THRESHOLD + 1) last = now;

	if (count <= LOG_COUNT_THRESHOLD)
		do_log(info);
	else if (count == LOG_COUNT_THRESHOLD + 1)
		syslog(SYSLOG_LEVEL, "More possible port scans follow");
}

/*
 * Process a TCP packet.
 */
void process_packet_ipv4(struct header *packet, int size)
{
	struct ip *ip;
	struct tcphdr *tcp;
	struct in_addr addr;
	unsigned short port;
	unsigned char flags;
	struct tms buf;
	clock_t now;
	struct hash_item *h_item;
	struct host_ipv4 *current;

	debug_printf("process packet\n");
	if(size < ((sizeof(struct ip) + sizeof(struct tcphdr))))
		return;

/* Get the IP and TCP headers */
	ip = &packet->ip;
	tcp = (struct tcphdr *)((char *)packet + ((int)ip->ip_hl << 2));

/* Sanity check */
	if (ip->ip_p != IPPROTO_TCP || (ip->ip_off & htons(IP_OFFMASK)) ||
	    (char *)tcp + sizeof(struct tcphdr) > (char *)packet + size)
		return;

/* Get the source address, destination port, and TCP flags */
	addr = ip->ip_src;
	port = tcp->th_dport;
	flags = tcp->th_flags;

/* We're using IP address 0.0.0.0 for a special purpose here, so don't let
 * them spoof us. */
	if (!addr.s_addr) return;

/* Use times(2) here not to depend on someone setting the time while we're
 * running; we need to be careful with possible return value overflows. */
	now = times(&buf);

/* Do we know this source address already? */
	h_item = hash_find_id(table_ipv4, (uint8_t *)&addr);
	if(h_item) {
		current = (struct host_ipv4*) h_item->data;

		if(!current) {
			fprintf(stderr, "process_packet_ipv4 - current is NULL\n");
			return;
		}
		debug_printf("process_packet_ipv4: found\n");

/* We know this address, and the entry isn't too old.  Update it. */
		if (now - current->timestamp <= scan_delay_threshold &&
		    now >= current->timestamp) {
	                debug_printf("process_packet_ipv4: timestamp ok\n");
/* Just update the TCP flags if we've seen this port already */
			for (int index = 0; index < current->count; index++)
			if (current->ports[index] == port) {
				current->flags_or |= flags;
				current->flags_and &= flags;
				return;
			}

/* ACK and/or RST to a new port?  This could be an outgoing connection. */
			if (flags & (TH_ACK | TH_RST)) return;

/* Packet to a new port, and not ACK: update the timestamp */
			current->timestamp = now;

/* Logged this scan already?  Then leave. */
			if (current->weight >= SCAN_WEIGHT_THRESHOLD) return;

/* Update the TCP flags */
			current->flags_or |= flags;
			current->flags_and &= flags;

/* Specify if destination address, source port, TOS, or TTL are not fixed */
			if (current->daddr.s_addr != ip->ip_dst.s_addr)
				current->flags |= HF_DADDR_CHANGING;
			if (current->sport != tcp->th_sport)
				current->flags |= HF_SPORT_CHANGING;
			if (current->tos != ip->ip_tos)
				current->flags |= HF_TOS_CHANGING;
			if (current->ttl != ip->ip_ttl)
				current->flags |= HF_TTL_CHANGING;

/* Update the total weight */
				current->weight += (ntohs(port) < 1024) ?
				PORT_WEIGHT_PRIV : PORT_WEIGHT_HIGH;

/* Got enough destination ports to decide that this is a scan?  Then log it. */
			if (current->weight >= SCAN_WEIGHT_THRESHOLD) {
				safe_log(current);
				return;
			}

/* Remember the new port */
			if (current->count < SCAN_MAX_COUNT - 1)
				current->ports[current->count++] = port;

			return;
		}

/* We know this address, but the entry is outdated.  Mark it unused and
 * remove from the hash table.  We'll allocate a new entry instead since
 * this one might get re-used too soon. */
		hash_remove(table_ipv4, h_item);
		free(current);
		free(h_item);
		h_item = NULL;
		current = NULL;
	}

/* We don't need an ACK from a new source address */
	if (flags & TH_ACK) return;

	//TODO check alloc
	current = calloc(1,sizeof(struct host_ipv4));
	h_item = calloc(1,sizeof(struct hash_item));

/* And fill in the fields */
	current->timestamp = now;
	current->start = time(NULL);
	current->saddr = addr;
	current->daddr = ip->ip_dst;
	current->sport = tcp->th_sport;
	current->count = 1;
	current->weight = (ntohs(port) < 1024) ?
		PORT_WEIGHT_PRIV : PORT_WEIGHT_HIGH;
	current->ports[0] = port;
	current->tos = ip->ip_tos;
	current->ttl = ip->ip_ttl;
	current->flags_or = current->flags_and = flags;
	current->flags = 0;

        h_item->data = (uint8_t *) current;
        h_item->id = (uint8_t *) &(current->saddr);

	hash_add(table_ipv4, h_item);
}

