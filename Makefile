CC = gcc
LD = $(CC)
RM = rm -f
CFLAGS = -Wall -g -Og -fomit-frame-pointer -std=c11
LDFLAGS = 

PCAP_H = -I/usr/include/pcap
PCAP_L = -lpcap

PROJ = scanlogd

OBJS_COMMON = main.o hash.o process_ipv4.o
OBJS = $(OBJS_COMMON) in_linux.o in_pcap.o

default:
	@echo "You need to choose a packet capture interface.  Use one of:"
	@echo "	make linux	to use the raw socket interface on Linux"
	@echo "	make libpcap	to use libpcap alone"
	@echo "See the man page for a short explanation of the interfaces."

linux: $(OBJS_COMMON) in_linux.o
	$(LD) $(LDFLAGS) $(OBJS_COMMON) in_linux.o -o scanlogd

libpcap: $(OBJS_COMMON) in_pcap.o
	$(LD) $(LDFLAGS) $(OBJS_COMMON) in_pcap.o $(PCAP_L) -o scanlogd

in_pcap.o: params.h in.h
	$(CC) $(CFLAGS) $(PCAP_H) -c in_pcap.c

main.o: main.h params.h in.h hash.h process_ipv4.h
in_linux.o: params.h in.h

.c.o:
	$(CC) $(CFLAGS) -c $*.c

clean:
	$(RM) $(PROJ) $(OBJS)
