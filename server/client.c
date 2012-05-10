#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <syslog.h>
#define MAX_LOG LOG_DEBUG
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)


#include "rohc_tunnel.h"

void close_client(void* tunnel)
{
	struct tunnel* client = (struct tunnel*) tunnel ;
	trace(LOG_INFO, "[%s] Properly close client", inet_ntoa(client->dest_address)) ;
	close(client->raw_socket) ;
	client->alive = -1 ; /* Mark to be deleted */
}

int new_client(int socket, int tun, int raw, struct tunnel** clients, struct tunnel_params params) {
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
	trace(LOG_DEBUG, "Allocating %p", clients[i]) ;

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

	clients[i]->params =  params ;

	clients[i]->close_callback = close_client ;

	return 0 ;
}


int start_client_tunnel(struct tunnel* client)
{
	/* Go thread, go ! */
	pthread_create(&(client->thread), NULL, new_tunnel, (void*)client) ;

	return 0 ;
}


