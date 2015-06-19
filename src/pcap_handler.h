#ifndef _PACKET_HANDLER_H_
#define _PACKET_HANDLER_H_

#include <pcap.h>

//const u_char *packet;
//struct pcap_pkthdr hdr;     /* pcap.h                    */
//struct ether_header *eptr;  /* net/ethernet.h            */
void pcap_cb(u_char*, const struct pcap_pkthdr*, const u_char*);
pcap_t *pcap_init(char*,char*);

#endif
