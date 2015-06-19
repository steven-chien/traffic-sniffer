/*
 * =====================================================================================
 *
 *       Filename:  packet_handler.c
 *
 *    Description:  Pakcet capturing callback
 *
 *        Version:  1.0
 *        Created:  Tuesday, June 16, 2015 04:42:24 HKT
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Steven Chien (sc), steven.chien@connect.polyu.hk
 *        Company:  The Hong Kong Polytechnic University, Hong Kong
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "pcap_handler.h"

/* just print a count every time we have a packet...                        */
void pcap_cb(u_char *data, const struct pcap_pkthdr *packet_hdr, const u_char *packet)
{
	int fd = (int)data;
	int linkhdrlen = 14;

	packet += linkhdrlen;
	struct ip *iphdr = (struct ip*)packet;
	printf("%s\n", inet_ntoa(iphdr->ip_src));
	write(fd, inet_ntoa(iphdr->ip_src), strlen(inet_ntoa(iphdr->ip_src))+1);
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  pcap_init
 *  Description:  Initialize pcap descriptor
 * =====================================================================================
 */
pcap_t *pcap_init(char *dev, char *filter)
{
	/*-----------------------------------------------------------------------------
	 *  Initialization
	 *-----------------------------------------------------------------------------*/
	struct bpf_program fp;      /* hold compiled program     */
	bpf_u_int32 maskp;          /* subnet mask               */
	bpf_u_int32 netp;           /* ip                        */
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_descr = NULL;
	int ret;

	/*-----------------------------------------------------------------------------
	 *  If interface is not specified, probe for one
	 *-----------------------------------------------------------------------------*/
	if(dev==NULL)
		dev = pcap_lookupdev(errbuff);
	if(dev==NULL)
		goto fail;

	/*-----------------------------------------------------------------------------
	 *  Lookup network number, net mask and create describtor
	 *-----------------------------------------------------------------------------*/
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuff);
	if(ret<0)
		goto fail;

	pcap_descr = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuff);
	if(pcap_descr==NULL)
		goto fail;

	/*-----------------------------------------------------------------------------
	 *  Compile rule and install filter to descriptor
	 *-----------------------------------------------------------------------------*/
	ret = pcap_compile(pcap_descr, &fp, filter, 0, netp);
	if(ret<0) {
		strcpy(errbuff, pcap_geterr(pcap_descr));
		goto fail;
	}

	ret = pcap_setfilter(pcap_descr, &fp);
	if(ret<0) {
		strcpy(errbuff, pcap_geterr(pcap_descr));
		goto fail;
	}

	return pcap_descr;

fail:
	fprintf(stderr, "%s\n", errbuff);
	if(pcap_descr!=NULL)
		pcap_close(pcap_descr);
	exit(1);
}		/* -----  end of function pcap_init  ----- */
