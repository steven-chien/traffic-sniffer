/*
 * =====================================================================================
 *
 *       Filename:  traffic_sniffer.c
 *
 *    Description:  A non block remote traffic sniffer
 *
 *        Version:  1.0
 *        Created:  Friday, June 19, 2015 02:42:48 HKT
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
#include <errno.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>

#include <signal.h>

#include "pcap_handler.h"

#define MAXEVENTS 64
#define PORT 8888

struct epoll_event *epoll_events = NULL;	/* reusable event structure and list of events to wait for */
pid_t pid = -1;
int port_no = -1;

void server()
{
	unsigned int sock = -1;			/* socket descr */
	unsigned int epoll_fd;			/* epoll descriptor */
	struct sockaddr_in serv_addr;		/* to specify server info */
	struct epoll_event event;		/* temp holding of event info */
	int ret;

	/* specify port number */
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	serv_addr.sin_addr.s_addr = INADDR_ANY;

	/* create a new socket instance */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock==-1)
		goto fail;

	/* bind socket to */
	ret = bind(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if(ret==-1)
		goto fail;

	/* set socket to non blocking mode */
	ret = fcntl(sock, F_SETFL, O_NONBLOCK);
	if(ret==-1)
		goto fail;

	/* start listening for incoming conn */
	ret = listen(sock, SOMAXCONN);
	if(ret==-1)
		goto fail;

	/* create epoll instance */
	epoll_fd = epoll_create1(0);
	if(epoll_fd==-1)
		goto fail;

	/* ask epoll to watching incoming and outgoing */
	event.data.fd = sock;
	event.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(epoll_fd,  EPOLL_CTL_ADD, sock, &event);
	if(ret==-1)
		goto fail;

	/* create 64 event holders */
	epoll_events = calloc(MAXEVENTS, sizeof(event));

	/* start waiting for connections... */
	while(1) {
		int n, i;
		n = epoll_wait(epoll_fd, epoll_events, MAXEVENTS, -1);

		/* handle epoll_events */
		for(i=0; i<n; i++) {
			if ((epoll_events[i].events & EPOLLERR) || (epoll_events[i].events & EPOLLHUP) || (!(epoll_events[i].events & EPOLLIN))) {
				/* error handling */
				fprintf(stderr, "%d hung up!\n", epoll_events[i].data.fd);
				close(epoll_events[i].data.fd);
			}
			else if(sock==epoll_events[i].data.fd) {
				/* accept incoming connections */
				while(1) {
					struct sockaddr in_addr;				/* storing client info */
					socklen_t in_len;
					int client_conn;					/* connection descr */
					char client_addr[NI_MAXHOST], client_port[NI_MAXSERV];	/* client address and port string */
					in_len = sizeof(in_addr);

					client_conn = accept(sock, &in_addr, &in_len);		/* accept client connection */
					if(client_conn==-1) {
						/* there is no available data right now, not an error */
						if(errno==EAGAIN || errno==EWOULDBLOCK) {
							break;
						}
						else {
							fprintf(stderr, "error: %s\n", strerror(errno));
							break;
						}
					}

					/* get connection info, return numeric ip addr */
					ret = getnameinfo(&in_addr, in_len, client_addr, sizeof(client_addr), client_port, sizeof(client_port), NI_NUMERICHOST | NI_NUMERICSERV);
					if(ret==0) {
						printf("accepted on %d, host=%s, port=%s\n", client_conn, client_addr, client_port);
						port_no = atoi(client_port);
					}

					/* set temp sock to non blocking mode */
					ret = fcntl(client_conn, F_SETFL, O_NONBLOCK);
					if(ret==-1) {
						goto fail;
					}

					/* register the new descriptor to epoll instance */
					event.data.fd = client_conn;
					event.events = EPOLLIN | EPOLLET;
					ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_conn, &event);
					if(ret==-1) {
						goto fail;
					}
				}
			}
			else {
				/* some data is received */
				while(1) {
					char recvBuf[512];
					int count = 0;
					/* read data from descr */
					count = read(epoll_events[i].data.fd, recvBuf, sizeof(recvBuf));
					if(count==-1) {
						if(errno!=EAGAIN)
							fprintf(stderr, "recv(): %s\n", strerror(errno));
						break;
					}
					else if(count==0) {
						/* the other side closed, deregister descr and close conn */
						printf("%d terminated!\n", epoll_events[i].data.fd);
						ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, epoll_events[i].data.fd, NULL);
						if(ret==-1)
							goto fail;

						close(epoll_events[i].data.fd);
						break;
					}

					/* echo back */
					if(pid==-1) {
						pid = fork();
						if(pid!=0) {
							ret = write(epoll_events[i].data.fd, recvBuf, count);
							if(ret==-1)
								goto fail;
						}
						else {
							char buf[512];
							//sprintf(buf, "!(dst host 127.0.0.1 and dst port %d)", port_no);
							sprintf(buf, "!(src port %d)", port_no);
							printf("rule: %s\n", buf);
							pcap_t *pcap_descr = pcap_init("wlp3s0", buf);
							pcap_loop(pcap_descr, -1, pcap_cb, (unsigned char*)epoll_events[i].data.fd);
						}
					}
					else if(pid!=-1) {
						kill(pid, SIGTERM);
						pid = -1;
						printf("Capturing ends!\n");
					}
				}
			}
		}
	}

	free(epoll_events);
	close(sock);
	return;
fail:
	fprintf(stderr, "error: %s\n", strerror(errno));
	if(epoll_events!=NULL) {
		free(epoll_events);
		epoll_events = NULL;
	}
	if(sock!=-1)
		close(sock);
	exit(1);
}

int main(int argc, char *argv[])
{
	server();
	return 0;
}
