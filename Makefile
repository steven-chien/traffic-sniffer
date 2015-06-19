CC=mips-openwrt-linux-uclibc-gcc
CC=clang

LDFLAG=-Wall -g
PCAP_LDFLAG=-lpcap


all: socket_poll.o
	$(CC) obj/*.o -o bin/traffic_sniffer $(LDFLAG)

socket_poll.o:
	$(CC) -c src/traffic_sniffer.c -o obj/traffic_sniffer.o $(LDFLAG)

clean:
	rm obj/*.o bin/*
