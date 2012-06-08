/* server.c -- Implements server side of the ROHC IP-IP tunnel

*/


#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <signal.h>

#include "rohc_tunnel.h"
#include "tun_helpers.h"

#include "client.h"
#include "messages.h"

// XXX : Config ?
#define MAX_CLIENTS 50

/// The maximal size of data that can be received on the virtual interface
#define TUNTAP_BUFSIZE 1518

#include <syslog.h>
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
	struct client** clients ;
	enum type_route type ;
} ;

/* Route function that will be threaded twice to route
from tun to fake_tun and from raw to fake_raw 

*/
void* route(void* arg)
{
	/* Getting args */
	int fd = ((struct route_args *)arg)->fd ;
	struct client** clients = ((struct route_args *)arg)->clients ;
	enum type_route type = ((struct route_args *)arg)->type ;

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
			return NULL ;
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
						write(clients[i]->tunnel.fake_tun[1], buffer, ret) ;
						break ;
					}
				} else {
					if (addr.s_addr == clients[i]->tunnel.dest_address.s_addr) {
						write(clients[i]->tunnel.fake_raw[1], buffer, ret) ;
					}
					break ;
				}
			}
		}
	}

	return NULL ;
}

struct client** clients ; 
void dump_stats(int sig)
{
	int j ;

	for (j=0; j<MAX_CLIENTS; j++) {
		if (clients[j] != NULL && clients[j]->tunnel.alive >= 0) {
			trace(LOG_NOTICE, "------------------------------------------------------") ;
			trace(LOG_NOTICE, "Client %s", inet_ntoa(clients[j]->tunnel.dest_address)) ;
			trace(LOG_NOTICE, "Stats : ") ;
			trace(LOG_NOTICE, " . Failed decompression : %d", clients[j]->tunnel.stats.decomp_failed) ;
			trace(LOG_NOTICE, " . Total  decompression : %d", clients[j]->tunnel.stats.decomp_total) ;
			trace(LOG_NOTICE, " . Failed compression   : %d", clients[j]->tunnel.stats.comp_failed) ;
			trace(LOG_NOTICE, " . Total  compression   : %d", clients[j]->tunnel.stats.comp_total) ;
			trace(LOG_NOTICE, " . Total compressed header size  : %d bytes", clients[j]->tunnel.stats.head_comp_size) ;
			trace(LOG_NOTICE, " . Total compressed packet size  : %d bytes", clients[j]->tunnel.stats.total_comp_size) ;
			trace(LOG_NOTICE, " . Total header size before comp : %d bytes", clients[j]->tunnel.stats.head_uncomp_size) ;
			trace(LOG_NOTICE, " . Total packet size before comp : %d bytes", clients[j]->tunnel.stats.total_uncomp_size) ;
		}
	}
}

int main(int argc, char *argv[])
{

	int serv_socket ;

	int tun, raw ;
	int tun_itf_id ;


	struct route_args route_args_tun ;
	struct route_args route_args_raw ;
	pthread_t route_thread; 

	fd_set rdfs;
	int max ;
	int j ;

	int ret ;
	sigset_t sigmask;

	
	clients = calloc(MAX_CLIENTS, sizeof(struct clients*)) ;

	/* Initialize logger */
	openlog("rohc_ipip_server", LOG_PID | LOG_PERROR, LOG_DAEMON) ;

	/* Signal for stats */
	signal(SIGUSR1, dump_stats) ;

	/* Create TCP socket */
	if ((serv_socket = create_tcp_socket(INADDR_ANY, atoi(argv[1]))) < 0) {
		perror("Can't open TCP socket") ;
		exit(1) ;
	}
	max = serv_socket ;

	/* params */
	struct tunnel_params params ;
    params.local_address       = inet_addr("192.168.99.1") ;
    params.packing             = 4 ;
    params.max_cid             = 14 ;
    params.is_unidirectional   = 1 ;
    params.wlsb_window_width   = 23 ;
    params.refresh             = 9 ;
    params.keepalive_timeout   = 60 ;
    params.rohc_compat_version = 1 ;

	/* TUN create */
	tun = create_tun("tun_ipip", &tun_itf_id) ;
	if (tun < 0) {
		trace(LOG_ERR, "Unable to create TUN device") ;
		return 1 ;
	}
	set_ip4(tun_itf_id, params.local_address, 24) ;

	/* TUN routing thread */
	route_args_tun.fd = tun ;
	route_args_tun.clients = clients ;
	route_args_tun.type = TUN ;
	pthread_create(&route_thread, NULL, route, (void*)&route_args_tun) ;

	/* RAW create */
	raw = create_raw() ;
	if (raw < -1) {
		trace(LOG_ERR, "Unable to create RAW socket") ;
		return 1 ;
	}

	/* RAW routing thread */
	route_args_raw.fd = raw ;
	route_args_raw.clients = clients ;
	route_args_raw.type = RAW ;
	pthread_create(&route_thread, NULL, route, (void*)&route_args_raw) ;

	struct timespec timeout ;

	struct timeval now ;

    /* mask signals during interface polling */
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGKILL);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGUSR1);

	/* Start listening and looping on TCP socket */
	while (1) {
		gettimeofday(&now, NULL) ;
		FD_ZERO(&rdfs); 
		FD_SET(serv_socket, &rdfs);		
		max = serv_socket ;

		for (j=0; j<MAX_CLIENTS; j++) {
			if (clients[j] != NULL && clients[j]->tunnel.alive >= 0) {
				// trace(LOG_DEBUG, "Client alive : %d", clients[j]->tunnel.alive) ;
				FD_SET(clients[j]->tcp_socket, &rdfs) ;
				max = (clients[j]->tcp_socket > max)? clients[j]->tcp_socket : max ;
			}
		}
		timeout.tv_sec = 1;
		timeout.tv_nsec = 0;

		if(pselect(max + 1, &rdfs, NULL, NULL, &timeout, &sigmask) == -1) {
			perror("select()");
		}

		if (FD_ISSET(serv_socket, &rdfs)) {
			ret = new_client(serv_socket, tun, clients, MAX_CLIENTS, params) ;
			if (ret < 0) {
				trace(LOG_ERR, "new_client returned %d\n", ret) ;
				/* TODO : HANDLE THAT */
			}
		}

		for (j=0; j<MAX_CLIENTS; j++) {
			if (clients[j] == NULL) {
				continue ;
			}
			// trace(LOG_DEBUG, "Client alive2 : %d", clients[j]->tunnel.alive) ;

			if (clients[j]->tunnel.alive == 1 && 
				(clients[j]->last_keepalive.tv_sec == -1 || 
				 clients[j]->last_keepalive.tv_sec + ceil(clients[j]->tunnel.params.keepalive_timeout/3) < now.tv_sec)) {
				/* send keepalive */
				keepalive(clients[j]->tcp_socket) ;
				gettimeofday(&(clients[j]->last_keepalive), NULL) ;
			} else if (clients[j]->tunnel.alive == -1) {
				/* free dead client */
				trace(LOG_DEBUG, "Freeing %p", clients[j]) ;
				close(clients[j]->tcp_socket) ;
				free(clients[j]) ;
				clients[j] = NULL ;
			} else if (FD_ISSET(clients[j]->tcp_socket, &rdfs)) {
				/* handle request */
				ret = handle_client_request(clients[j], params) ;
				if (ret < 0) {
					if (clients[j]->tunnel.alive > 0) {
						trace(LOG_WARNING, "[%s] Client disconnected", inet_ntoa(clients[j]->tunnel.dest_address)) ;
						clients[j]->tunnel.alive = 0 ;
					}
				}
			}
		}
	}

	return 0 ;
}
