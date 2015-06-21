#ifndef _PACKET_HANDLER_H_
#define _PACKET_HANDLER_H_

#include <signal.h>
#include <sys/types.h>
#include <pcap.h>

static pid_t pid = -1;
static char *interface = NULL;

void pcap_start(char*, int);
void pcap_stop();
void pcap_set_interface(const char*);
void pcap_cb(u_char*, const struct pcap_pkthdr*, const u_char*);
pcap_t *pcap_init(char*,char*);

#endif
