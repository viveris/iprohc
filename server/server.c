/* server.c -- Implements server side of the ROHC IP-IP tunnel

Description :

The server will listen on a TCP socket for incoming client. A client
will send command in netstrings
Protocol version


Client commands :
 * 6:connect, : Connection asked, a raw socket is created with the incoming
				client IP as destination. An IP address is picked for this client.
				The server then answer :
	- If ok : 1x:xxxxx,y:yyyyy with x the IP address and y a token generated 
	IP address of the endpoint, 
	- Else  : 0z:zzzzz, with z a human readable error message
 * 9:disconnect,x:xxxxxx : Disconnection asked, raw socket is destroyed.
						   The socket is retrieved by the token (xxxxx) 
						   Then server then answer
	- If ok : 1
	- Else  : 0

Client are described by a structure containing its raw socket and its VPN address

*/


#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <linux/if_tun.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <syslog.h>

#include "rohc_tunnel.h"
#include "tun_helpers.h"


// XXX : Config ?
#define MAX_CLIENTS 50

/// The maximal size of data that can be received on the virtual interface
#define TUNTAP_BUFSIZE 1518

#define MAX_LOG LOG_DEBUG
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)

/* Create TCP socket for communication with clients */
int create_tcp_socket(uint32_t address, uint16_t port) {

	int sock = socket(AF_INET, SOCK_STREAM, 0) ;
	int on = 1; 
	setsockopt(sock,SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)); 

	struct	sockaddr_in servaddr ;
	servaddr.sin_family	  = AF_INET;
	servaddr.sin_addr.s_addr = htonl(address);
	servaddr.sin_port		= htons(port);

	if (bind(sock,  (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
		perror("Bind failed") ;
	
	if (listen(sock, 10) < 0)
		perror("Listen failed") ;

	return sock ;
}

struct route_args {
	int tun ;
	struct tunnel** clients ;
} ;

/* Thread that will be called to monitor tun and route */
void* route(void* arg)
{
	/* Getting args */
	int tun = ((struct route_args *)arg)->tun ;
	struct tunnel** clients = ((struct route_args *)arg)->clients ;
	int i ;

	int ret;
    static unsigned char buffer[TUNTAP_BUFSIZE];
    unsigned int buffer_len = TUNTAP_BUFSIZE;
	struct in_addr addr;

	/// XXX : uint32
	unsigned int* dest_ip ;
	
	trace(LOG_INFO, "Initializing routing thread\n") ;

	while ((ret = read(tun, buffer, buffer_len))) {
		if(ret < 0 || ret > buffer_len)
		{
			trace(LOG_ERR, "read failed: %s (%d)\n", strerror(errno), errno);
		}

		trace(LOG_DEBUG, "Read %d bytes\n", ret) ;
		dest_ip = (unsigned int*) &buffer[20];
		addr.s_addr = *dest_ip ;
		trace(LOG_DEBUG, "Packet destination : %s\n", inet_ntoa(addr)) ;
		for (i=0; i < MAX_CLIENTS; i++) {
			if (clients[i] != NULL) {
				trace(LOG_DEBUG, "Checking %d against %d\n", addr.s_addr, clients[i]->local_address.s_addr) ;

				if (addr.s_addr == clients[i]->local_address.s_addr) {
					write(clients[i]->fake_tun[1], buffer, ret) ;
					break ;
				}
			}
		}

	}

	return NULL ;
}

int new_client(int socket, int tun, struct tunnel** clients) {
	int conn; 
	struct	sockaddr_in src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	struct in_addr local;

	int i = 4 ;

	/* New client */
	conn = accept(socket, (struct sockaddr*)&src_addr, &src_addr_len) ;
	if (conn < 0) {
		perror("Fail accept\n") ;
	}
	trace(LOG_INFO, "Connection from %s (%d)\n", inet_ntoa(src_addr.sin_addr), src_addr.sin_addr.s_addr) ;

	/* client creation parameters */
	trace(LOG_DEBUG, "Creation of client") ;
	clients[i] = malloc(sizeof(struct tunnel)) ;

	/* dest_addr */
	clients[i]->dest_address  = src_addr.sin_addr ;
	
	/* local_addr */
	local.s_addr = htonl(inet_network("192.168.99.23")) ;
	clients[i]->local_address = local ;

	clients[i]->tcp_socket = conn ;
	
	/* set tun */
	clients[i]->tun = tun ; /* real tun device */
	if (pipe(clients[i]->fake_tun) < 0) {
		perror("Can't open pipe for tun") ;
		/* TODO  : Flush */
		return 1 ;
	}

	/* Go thread, go ! */
	pthread_create(&(clients[i]->thread), NULL, new_tunnel, (void*)clients[i]) ;

	return 0 ;
}

int handle_client_request(struct tunnel* client) {
	char buffer[1024] ;

	recv(client->tcp_socket, buffer, 1024, 0) ;

	return 0 ;
}

int main(int argc, char *argv[]) {

	int serv_socket ;

	int tun ;
	int tun_itf_id ;


	struct route_args route_args ;
	pthread_t route_thread; 

	struct tunnel** clients = calloc(MAX_CLIENTS, sizeof(struct tunnel*)) ;
	fd_set rdfs;
	int max ;
	int j ;

	/* Initialize logger */
	openlog("rohc_ipip_server", LOG_PID | LOG_PERROR, LOG_DAEMON) ;


	if ((serv_socket = create_tcp_socket(INADDR_ANY, 1989)) < 0) {
		perror("Can't open TCP socket") ;
		exit(1) ;
	}
	max = serv_socket ;

	/* TUN create */
	tun = create_tun("tun_ipip", &tun_itf_id) ;
	set_ip4(tun_itf_id, htonl(inet_network("192.168.99.1")), 24) ;

	/* Routing thread */
	route_args.tun = tun ;
	route_args.clients = clients ;
	pthread_create(&route_thread, NULL, route, (void*)&route_args) ;

	while (1) {
		FD_ZERO(&rdfs); 
		FD_SET(serv_socket, &rdfs);		
		for (j=0; j<MAX_CLIENTS; j++) {
			if (clients[j] != NULL) {
				FD_SET(clients[j]->tcp_socket, &rdfs) ;
				max = (clients[j]->tcp_socket > max)? clients[j]->tcp_socket : max ;
			}
		}

		if(select(max + 1, &rdfs, NULL, NULL, NULL) == -1) {
			perror("select()");
			exit(errno);
		}

		if (FD_ISSET(serv_socket, &rdfs)) {
			new_client(serv_socket, tun, clients) ;
		}

		for (j=0; j<MAX_CLIENTS; j++) {
			if (clients[j] != NULL && FD_ISSET(clients[j]->tcp_socket, &rdfs)) {
				handle_client_request(clients[j]) ;												
			}
		}
	}

	return 0 ;
}
