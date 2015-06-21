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
#include <signal.h>
#include <sys/wait.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <json-c/json.h>

#include "pcap_handler.h"

/*-----------------------------------------------------------------------------
 *  pcap descriptor
 *-----------------------------------------------------------------------------*/
static pcap_t *pcap_descr = NULL;

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  pcap_term_handler
 *  Description:  Handle SIGTERM by child process
 * =====================================================================================
 */
void pcap_term_handler(int signum, siginfo_t *info, void *ptr)
{
	if(signum==SIGTERM) {
		/* break pcap_loop */
		if(pcap_descr!=NULL) {
			printf("Process %d: SIGTERM caught, breaking pcap loop and exit!\n", getpid());
			pcap_breakloop(pcap_descr);
			pcap_close(pcap_descr);
		}

		/* free interface string if exist */
		if(interface!=NULL) {
			free(interface);
			interface = NULL;
		}

		/* terminate itself */
		exit(0);
	}
}		/* -----  end of function pcap_term_handler  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  pcap_set_interface
 *  Description:  Set which interface to capture
 * =====================================================================================
 */
void pcap_set_interface(const char *interface2set)
{
	if(interface!=NULL)
		free(interface);
	interface = (char*)calloc(strlen(interface2set)+1, sizeof(char));
	strcpy(interface, interface2set);
	printf("new interface: %s\n", interface);
}		/* -----  end of function pcap_set_interface  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  pcap_stop
 *  Description:  To kill child process by parent
 * =====================================================================================
 */
void pcap_stop()
{
	/* kill child process if exist */
	if(pid!=-1) {
		kill(pid, SIGTERM);
		wait(NULL);
		pid = -1;
	}
}		/* -----  end of function pcap_stop  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  pcap_start
 *  Description:  Compile rules, init descriptor and start capture loop
 * =====================================================================================
 */
void pcap_start(char *ip, int fd)
{
	char rule[256];

	if(pid==-1) {
		if(ip!=NULL) {
			sprintf(rule, "!(dst host %s and dst port 8888)", ip);
		}
		else {
			printf("error!\n");
			exit(1);
		}
		printf("Rule to compile: %s\n", rule);

		/*-----------------------------------------------------------------------------
		 *  Fork a child process with capture loop
		 *-----------------------------------------------------------------------------*/
		pid = fork();
		if(pid==0) {
			/* install signal handler */
			struct sigaction sigterm_handle;
			sigterm_handle.sa_sigaction = pcap_term_handler;
			sigterm_handle.sa_flags = SA_SIGINFO;
			sigaction(SIGTERM, &sigterm_handle, NULL);

			/* init pcap descriptor and start capturing loop */
			pcap_descr = pcap_init(interface, rule);
			write(fd, "{\"msg\":\"Capture Starts!\"}", 26);
			sleep(1);
			pcap_loop(pcap_descr, -1, pcap_cb, (unsigned char*)fd);
		}
	}
}		/* -----  end of function pcap_start  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  pcap_cb
 *  Description:  Callback for each packet captured by pcap_loop
 * =====================================================================================
 */
void pcap_cb(u_char *data, const struct pcap_pkthdr *packet_hdr, const u_char *packet)
{
	/* extract descriptor and linklayer size */
	int fd = (int)data;
	int linkhdrlen = 14;

	/* prepare json objects */
	json_object *jobj = json_object_new_object();

	json_object *time = json_object_new_int64((packet_hdr->ts.tv_sec)*1000 + packet_hdr->ts.tv_usec);
	json_object_object_add(jobj, "time", time);

	json_object *src = json_object_new_object();
	json_object *dst = json_object_new_object();

	json_object *dst_port, *src_port, *dst_addr, *src_addr;
	json_object *iphr_len, *ip_len, *protocol;
	json_object *tcp_len;

	/*-----------------------------------------------------------------------------
	 *  Start extracting info from packet
	 *-----------------------------------------------------------------------------*/
	packet += linkhdrlen;
	struct ip *ip_hdr = (struct ip*)packet;
	
	/* source and dest ip */
	src_addr = json_object_new_string(inet_ntoa(ip_hdr->ip_src));
	json_object_object_add(src, "addr", src_addr);
	dst_addr = json_object_new_string(inet_ntoa(ip_hdr->ip_dst));
	json_object_object_add(dst, "addr", dst_addr);

	/* total packet length */
	ip_len = json_object_new_int(ntohs(ip_hdr->ip_len));
	json_object_object_add(jobj, "pk_len", ip_len);

	/* ip header length */
	iphr_len = json_object_new_int((ip_hdr->ip_hl)*4);
	json_object_object_add(jobj, "iphr_len", iphr_len);

	/*-----------------------------------------------------------------------------
	 *  Strip IP header
	 *-----------------------------------------------------------------------------*/
	struct tcphdr *tcp_hdr = (struct tcphdr*)(packet + (ip_hdr->ip_hl) * 4);
	struct udphdr *udp_hdr = (struct udphdr*)(packet + (ip_hdr->ip_hl) * 4);

	/*-----------------------------------------------------------------------------
	 *  Extract protocol and header sizes
	 *-----------------------------------------------------------------------------*/
	switch(ip_hdr->ip_p) {
		case 6:
			/* protocol */
			protocol = json_object_new_string("TCP");

			/* extract source and dest tcp port */
			src_port = json_object_new_int(htons(tcp_hdr->source));
			json_object_object_add(src, "port", src_port);
			
			dst_port = json_object_new_int(htons(tcp_hdr->dest));
			json_object_object_add(dst, "port", dst_port);

			/* extract tcp header size */
			tcp_len = json_object_new_int((tcp_hdr->doff)*4);
			json_object_object_add(jobj, "tcphdr_len", tcp_len);

			break;
		case 17:
			/* protocol */
			protocol = json_object_new_string("UDP");

			/* extract sorce and dest udp port */
			src_port = json_object_new_int(htons(udp_hdr->source));
			json_object_object_add(src, "port", src_port);

			dst_port = json_object_new_int(htons(udp_hdr->dest));
			json_object_object_add(dst, "port", dst_port);

			break;
	}

	/*-----------------------------------------------------------------------------
	 *  Added destination, source and protocol to json object
	 *-----------------------------------------------------------------------------*/
	json_object_object_add(jobj, "dst", dst);
	json_object_object_add(jobj, "src", src);
	json_object_object_add(jobj, "protocol", protocol);

	/*-----------------------------------------------------------------------------
	 *  Extract string from json object
	 *-----------------------------------------------------------------------------*/
	const char *str = json_object_get_string(jobj);
	printf("%s\n", str);

	/*-----------------------------------------------------------------------------
	 *  Write result to client
	 *-----------------------------------------------------------------------------*/
	write(fd, str, strlen(str)+1);
	json_object_put(jobj);
	fflush(stdout);
}		/* -----  end of function pcap_cb  ----- */

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
