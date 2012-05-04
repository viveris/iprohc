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
#include "tlv.h"


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

/* Thread that will be called to monitor tun or raw and route */
enum type_route { TUN, RAW } ;

struct route_args {
	int fd ;
	struct tunnel** clients ;
	enum type_route type ;
} ;


void* route(void* arg)
{
	/* Getting args */
	int fd = ((struct route_args *)arg)->fd ;
	struct tunnel** clients = ((struct route_args *)arg)->clients ;
	int type = ((struct route_args *)arg)->type ;
	int i ;

	int ret;
    static unsigned char buffer[TUNTAP_BUFSIZE];
    unsigned int buffer_len = TUNTAP_BUFSIZE;
	struct in_addr addr;

	uint32_t* src_ip ;
	uint32_t* dest_ip ;
	
	trace(LOG_INFO, "Initializing routing thread\n") ;

	while ((ret = read(fd, buffer, buffer_len))) {
		if(ret < 0 || ret > buffer_len)
		{
			trace(LOG_ERR, "read failed: %s (%d)\n", strerror(errno), errno);
		}

		trace(LOG_DEBUG, "Read %d bytes\n", ret) ;
		if (type == TUN) {
			dest_ip = (uint32_t*) &buffer[20];
			addr.s_addr = *dest_ip ;
			trace(LOG_DEBUG, "Packet destination : %s\n", inet_ntoa(addr)) ;
		} else {
			src_ip = (uint32_t*) &buffer[12];
			addr.s_addr = *src_ip ;
			trace(LOG_DEBUG, "Packet source : %s\n", inet_ntoa(addr)) ;
		}

		for (i=0; i < MAX_CLIENTS; i++) {
			if (clients[i] != NULL) {
				if (type == TUN) {
					if (addr.s_addr == clients[i]->local_address.s_addr) {
						write(clients[i]->fake_tun[1], buffer, ret) ;
						break ;
					}
				} else {
					if (addr.s_addr == clients[i]->dest_address.s_addr) {
						write(clients[i]->fake_raw[1], buffer, ret) ;
					}
					break ;
				}
			}
		}
	}

	return NULL ;
}

int new_client(int socket, int tun, int raw, struct tunnel** clients) {
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

	/* set raw */
	clients[i]->raw_socket = raw ; /* real tun device */
	if (pipe(clients[i]->fake_raw) < 0) {
		perror("Can't open pipe for tun") ;
		/* TODO  : Flush */
		return 1 ;
	}


	return 0 ;
}

int handle_connect(struct tunnel* client)
{
	struct tunnel_params params ;
	char tlv[1024] ;
	tlv[0] = C_CONNECT_OK ;
	size_t len = 1 ;
	
    params.local_address       = client->local_address.s_addr ;
    params.packing             = 5 ;
    params.max_cid             = 14 ;
    params.is_unidirectional   = 1 ;
    params.wlsb_window_width   = 23 ;
    params.refresh             = 9 ;
    params.keepalive_timeout   = 1000 ;
    params.rohc_compat_version = 1 ;

	len += gen_connect(tlv+1, params) ;
	send(client->tcp_socket, tlv, len, 0) ;

	return 0 ;
}

int close_client(struct tunnel* client)
{
	client->alive = 0 ;
	close(client->raw_socket) ;
	free(client) ;

	return 0 ;
}

int start_client_tunnel(struct tunnel* client)
{
	/* Go thread, go ! */
	pthread_create(&(client->thread), NULL, new_tunnel, (void*)client) ;

	return 0 ;
}

int handle_client_request(struct tunnel* client) {
	char buf[1024] ;
	int length;
	char* cur ;
	char* bufmax;


	length = recv(client->tcp_socket, buf, 1024, 0) ;
	if (length == 0) {
		return -1 ;
	}
	bufmax = buf + length ;
	trace(LOG_DEBUG, "[%s] Received %d bytes on TCP socket", inet_ntoa(client->dest_address),
					 length) ;
	cur = buf ;
	while (cur < bufmax) {
		switch (*cur) {
			case C_CONNECT:
				trace(LOG_INFO, "[%s] Connection asked, negotating parameters", inet_ntoa(client->dest_address)) ;
				handle_connect(client) ;
				cur++ ;
				break ;
			case C_CONNECT_DONE :
				trace(LOG_INFO, "[%s] Connection started", inet_ntoa(client->dest_address)) ;
				start_client_tunnel(client) ;
				cur++ ;
				break;
		}
	}
	return 0 ;
}

int main(int argc, char *argv[]) {

	int serv_socket ;

	int tun, raw ;
	int tun_itf_id ;


	struct route_args route_args_tun ;
	struct route_args route_args_raw ;
	pthread_t route_thread; 

	struct tunnel** clients = calloc(MAX_CLIENTS, sizeof(struct tunnel*)) ;
	fd_set rdfs;
	int max ;
	int j ;

	int ret ;

	/* Initialize logger */
	openlog("rohc_ipip_server", LOG_PID | LOG_PERROR, LOG_DAEMON) ;


	if ((serv_socket = create_tcp_socket(INADDR_ANY, 1989)) < 0) {
		perror("Can't open TCP socket") ;
		exit(1) ;
	}
	max = serv_socket ;

	/* TUN create */
	tun = create_tun("tun_ipip", &tun_itf_id) ;
	if (tun < 0) {
		trace(LOG_ERR, "Unable to create TUN device") ;
		return 1 ;
	}
	set_ip4(tun_itf_id, htonl(inet_network("192.168.99.1")), 24) ;

	/* TUN routing thread */
	route_args_tun.fd = tun ;
	route_args_tun.clients = clients ;
	route_args_tun.type = TUN ;
	pthread_create(&route_thread, NULL, route, (void*)&route_args_tun) ;

	/* RAW create */
	raw = create_raw() ;
	if (raw < -1) {
		trace(LOG_ERR, "Unable to create TUN device") ;
		return 1 ;
	}

	/* RAW routing thread */
	route_args_raw.fd = raw ;
	route_args_raw.clients = clients ;
	route_args_raw.type = RAW ;
	pthread_create(&route_thread, NULL, route, (void*)&route_args_raw) ;

	/* Start listening and looping on TCP socket */
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
			new_client(serv_socket, tun, raw, clients) ;
		}

		for (j=0; j<MAX_CLIENTS; j++) {
			if (clients[j] != NULL && FD_ISSET(clients[j]->tcp_socket, &rdfs)) {
				ret = handle_client_request(clients[j]) ;
				if (ret < 0) {
					trace(LOG_WARNING, "[%s] Client disconnected", inet_ntoa(clients[j]->dest_address)) ;
					close_client(clients[j]) ;
					clients[j] = NULL ;
				}

			}
		}
	}

	return 0 ;
}
