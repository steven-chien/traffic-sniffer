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
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <json-c/json.h>

#include "pcap_handler.h"

/* just print a count every time we have a packet...                        */
void pcap_cb(u_char *data, const struct pcap_pkthdr *packet_hdr, const u_char *packet)
{
	/* capture current time */
	struct timespec timer;
	clock_gettime(CLOCK_MONOTONIC, &timer);

	/* extract descriptor and linklayer size */
	int fd = (int)data;
	int linkhdrlen = 14;

	/* prepare json objects */
	json_object *jobj = json_object_new_object();

	json_object *time = json_object_new_int64(timer.tv_nsec);
	json_object_object_add(jobj, "time", time);

	json_object *src = json_object_new_object();
	json_object *dst = json_object_new_object();

	json_object *dst_port, *src_port, *dst_addr, *src_addr;
	json_object *ip_len, *protocol;
	json_object *tcp_len;

	/* extract ip and tcp header */
	packet += linkhdrlen;
	struct ip *ip_hdr = (struct ip*)packet;
	

	/* source and dest ip */
	src_addr = json_object_new_string(inet_ntoa(ip_hdr->ip_src));
	json_object_object_add(src, "addr", src_addr);
	dst_addr = json_object_new_string(inet_ntoa(ip_hdr->ip_dst));
	json_object_object_add(dst, "addr", dst_addr);

	/* protocol */
	protocol = json_object_new_int(ip_hdr->ip_p);
	json_object_object_add(jobj, "protocol", protocol);

	/* ip packet length */
	ip_len = json_object_new_int(ip_hdr->ip_len);
	json_object_object_add(jobj, "ip_len", ip_len);

	/* use the following depending on protocol */
	struct tcphdr *tcp_hdr = (struct tcphdr*)(packet + ip_hdr->ip_hl);
	struct udphdr *udp_hdr = (struct udphdr*)(packet + ip_hdr->ip_hl);

	switch(ip_hdr->ip_p) {
		case 6:
			/* extract source and dest tcp port */
			src_port = json_object_new_int(htons(tcp_hdr->source));
			json_object_object_add(src, "port", src_port);
			
			dst_port = json_object_new_int(htons(tcp_hdr->dest));
			json_object_object_add(dst, "port", dst_port);

			tcp_len = json_object_new_int(tcp_hdr->doff);
			json_object_object_add(jobj, "tcp_len", tcp_len);
			break;
		case 17:
			/* extract sorce and dest udp port */
			src_port = json_object_new_int(htons(udp_hdr->source));
			json_object_object_add(src, "port", src_port);

			dst_port = json_object_new_int(htons(udp_hdr->dest));
			json_object_object_add(dst, "port", dst_port);

			break;
	}

	/* finished constructing src and dest info */
	json_object_object_add(jobj, "dst", dst);
	json_object_object_add(jobj, "src", src);

	const char *str = json_object_get_string(jobj);

	printf("%s\n", str);

	write(fd, str, strlen(str)+1);
	json_object_put(jobj);
	fflush(stdout);
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

//	/*-----------------------------------------------------------------------------
//	 *  Compile rule and install filter to descriptor
//	 *-----------------------------------------------------------------------------*/
//	ret = pcap_compile(pcap_descr, &fp, filter, 0, netp);
//	if(ret<0) {
//		strcpy(errbuff, pcap_geterr(pcap_descr));
//		goto fail;
//	}
//
//	ret = pcap_setfilter(pcap_descr, &fp);
//	if(ret<0) {
//		strcpy(errbuff, pcap_geterr(pcap_descr));
//		goto fail;
//	}

	return pcap_descr;

fail:
	fprintf(stderr, "%s\n", errbuff);
	if(pcap_descr!=NULL)
		pcap_close(pcap_descr);
	exit(1);
}		/* -----  end of function pcap_init  ----- */
