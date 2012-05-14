#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#include <syslog.h>
#define MAX_LOG LOG_DEBUG
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)


#include "rohc_tunnel.h"
#include "client.h"

void close_tunnel(void* v_tunnel)
{
	struct tunnel* tunnel = (struct tunnel*) v_tunnel ;
	trace(LOG_INFO, "[%s] Properly close client", inet_ntoa(tunnel->dest_address)) ;
	close(tunnel->raw_socket) ;
	tunnel->alive = -1 ; /* Mark to be deleted */
}

int new_client(int socket, int tun, int raw, struct client** clients, int max_clients, struct tunnel_params params) {
	int conn; 
	struct	sockaddr_in src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	struct in_addr local;
	int i = 0 ;

	/* New client */
	conn = accept(socket, (struct sockaddr*)&src_addr, &src_addr_len) ;
	if (conn < 0) {
		perror("Fail accept\n") ;
	}
	trace(LOG_INFO, "Connection from %s (%d)\n", inet_ntoa(src_addr.sin_addr), src_addr.sin_addr.s_addr) ;

	/* client creation parameters */
	trace(LOG_DEBUG, "Creation of client") ;
	
	while (clients[i] != NULL && i < max_clients) { i++; }
	if (i == max_clients) {
		return -2 ;
	}

	clients[i] = malloc(sizeof(struct client)) ;
	trace(LOG_DEBUG, "Allocating %p", clients[i]) ;
	clients[i]->tcp_socket = conn ;

	/* dest_addr */
	clients[i]->tunnel.dest_address  = src_addr.sin_addr ;
	/* local_addr */
	local.s_addr = inet_addr("192.168.99.23") ;
	clients[i]->local_address = local ;

	/* set tun */
	clients[i]->tunnel.tun = tun ; /* real tun device */
	if (socketpair(AF_UNIX, SOCK_RAW, 0, clients[i]->tunnel.fake_tun) < 0) {
		perror("Can't open pipe for tun") ;
		/* TODO  : Flush */
		return 1 ;
	}

	/* set raw */
	clients[i]->tunnel.raw_socket = raw ; /* real tun device */
	if (socketpair(AF_UNIX, SOCK_RAW, 0, clients[i]->tunnel.fake_raw) < 0) {
		perror("Can't open pipe for tun") ;
		/* TODO  : Flush */
		return -1 ;
	}

	clients[i]->tunnel.params =  params ;
	clients[i]->tunnel.alive =   0 ;
	clients[i]->tunnel.close_callback = close_tunnel ;

	clients[i]->last_keepalive.tv_sec = -1 ;

	trace(LOG_DEBUG, "Created") ;

	return i ;
}


int start_client_tunnel(struct client* client)
{
	/* Go threads, go ! */
	pthread_create(&(client->thread_tunnel), NULL, new_tunnel, (void*)(&(client->tunnel))) ;
	return 0 ;
}


