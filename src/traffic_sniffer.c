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
#include <signal.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>

#include <json-c/json.h>

#include "pcap_handler.h"

#define MAXEVENTS 64
#define PORT 8888

//static char client_addr[NI_MAXHOST], client_port[NI_MAXSERV];	/* client address and port string */
static char *client_addr =NULL, *client_port = NULL;	/* client address and port string */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  server
 *  Description:  Non-blocking server loop to handle connections
 * =====================================================================================
 */
void server()
{
	/*-----------------------------------------------------------------------------
	 *  Define server info, create new socket and bind
	 *-----------------------------------------------------------------------------*/
	unsigned int sock = -1;
	unsigned int epoll_fd;
	struct sockaddr_in serv_addr;
	struct epoll_event event;
	struct epoll_event *epoll_events = NULL;
	int ret;

	/* specify port number */
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	serv_addr.sin_addr.s_addr = INADDR_ANY;

	/* create a new socket descr */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock==-1)
		goto fail;

	/* bind socket to */
	ret = bind(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if(ret==-1)
		goto fail;

	/*-----------------------------------------------------------------------------
	 *  Set socket to non-block mode, start listening and create epoll instance
	 *-----------------------------------------------------------------------------*/
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

	/*-----------------------------------------------------------------------------
	 *  Server main loop
	 *-----------------------------------------------------------------------------*/
	while(1) {
		int n, i;
		n = epoll_wait(epoll_fd, epoll_events, MAXEVENTS, -1);

		/* handle epoll events */
		for(i=0; i<n; i++) {
			if ((epoll_events[i].events & EPOLLERR) || (epoll_events[i].events & EPOLLHUP) || (!(epoll_events[i].events & EPOLLIN))) {
				/*-----------------------------------------------------------------------------
				 *  Handle error
				 *-----------------------------------------------------------------------------*/
				fprintf(stderr, "%d hung up!\n", epoll_events[i].data.fd);
				close(epoll_events[i].data.fd);
			}
			else if(sock==epoll_events[i].data.fd) {
				/*-----------------------------------------------------------------------------
				 *  Accept new connections and add to epoll control 
				 *-----------------------------------------------------------------------------*/
				while(1) {
					struct sockaddr in_addr;				/* storing client info */
					socklen_t in_len;
					int client_conn;					/* connection descr */
					in_len = sizeof(in_addr);

					client_conn = accept(sock, &in_addr, &in_len);		/* accept client connection */
					if(client_conn==-1) {
						/* there is no available data for reading right now, not an error */
						if(errno==EAGAIN || errno==EWOULDBLOCK) {
							break;
						}
						else {
							fprintf(stderr, "error: %s\n", strerror(errno));
							break;
						}
					}

					/* check if other client is connected */
					/* plan to implement a link list in the future, to support multiple sniffing */
					if(client_addr!=NULL && client_port!=NULL) {
						write(client_conn, "{\"msg\":\"One client a time\"}", 29);
						close(client_conn);
						break;
					}

					/* capture addr and port */
					client_addr = calloc(NI_MAXHOST+1, sizeof(char));
					client_port = calloc(NI_MAXSERV+1, sizeof(char));

					ret = getnameinfo(&in_addr, in_len, client_addr, NI_MAXHOST, client_port, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
					if(ret==0) {
						printf("accepted on %d, host=%s, port=%s\n", client_conn, client_addr, client_port);
					}

					/* set temp sock to non blocking mode */
					ret = fcntl(client_conn, F_SETFL, O_NONBLOCK);
					if(ret==-1) {
						goto fail;
					}

					/* register the new descriptor to epoll */
					event.data.fd = client_conn;
					event.events = EPOLLIN | EPOLLET;
					ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_conn, &event);
					if(ret==-1) {
						goto fail;
					}
				}
			}
			else {
				/*-----------------------------------------------------------------------------
				 *  Handle received data
				 *-----------------------------------------------------------------------------*/
				while(1) {
					/* prepare to read from command */
					char recvBuf[512];
					memset(&recvBuf, 0, sizeof(recvBuf));

					/* read data from descr */
					int count = 0;
					count = read(epoll_events[i].data.fd, recvBuf, sizeof(recvBuf));

					if(count==-1) {
						/*-----------------------------------------------------------------------------
						 *  No data avaliable for reading, break
						 *-----------------------------------------------------------------------------*/
						if(errno!=EAGAIN)
							fprintf(stderr, "recv(): %s\n", strerror(errno));
						break;
					}
					else if(count==0) {
						/*-----------------------------------------------------------------------------
						 *  The other end closed, deregister connection and close socket
						 *-----------------------------------------------------------------------------*/
						printf("%d terminated!\n", epoll_events[i].data.fd);

						/* deregister */
						ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, epoll_events[i].data.fd, NULL);
						if(ret==-1)
							goto fail;

						close(epoll_events[i].data.fd);

						/* free address and port string */
						free(client_addr);
						client_addr = NULL;

						free(client_port);
						client_port = NULL;

						/* kill child if a child was initiated */
						pcap_stop();

						break;
					}
					else {
						/*-----------------------------------------------------------------------------
						 *  Data ready for handling
						 *-----------------------------------------------------------------------------*/
						printf("Received: %s\n\n", recvBuf);

						/* parse command */
						json_object *jobj = json_tokener_parse(recvBuf);
						if(jobj!=NULL) {
							/* extract instruction */
							json_object *instruction;
							json_object_object_get_ex(jobj, "instr", &instruction);

							if(instruction!=NULL) {
								const char *instr = json_object_get_string(instruction);
								if(strcmp(instr, "config")==0) {
									/* set interface */
									json_object *interface;
									if(json_object_object_get_ex(jobj, "interface", &interface)!=0) {
										pcap_set_interface(json_object_get_string(interface));
									}
								}
								else if(strcmp(instr, "start")==0) {
									/* start capturing */
									pcap_start(client_addr, epoll_events[i].data.fd);
								}
								else if(strcmp(instr, "stop")==0) {
									/* kill child process */
									pcap_stop();
									printf("Capturing stoped!\n");
									write(epoll_events[i].data.fd, "{\"msg\":\"Capture Ends!\"}", 24);
								}
								else {
									printf("Command not found!\n");
								}
							}
							/* free json */
							json_object_put(jobj);
						}
					}
				}
			}
		}
	}

	/* close connection */
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
}               /* -----  end of function server  ----- */

int main(int argc, char *argv[])
{
	server();
	return 0;
}
