#include <sys/types.h>
#include <sys/time.h>

#include "tlv.h"
#include "rohc_tunnel.h"

#include "client.h"

#include "log.h"

int handle_connect(struct client* client)
{
	char tlv[1024] ;
	tlv[0] = C_CONNECT_OK ;
	size_t len = 1 ;

	len += gen_connect(tlv+1, client->tunnel.params) ;
	send(client->tcp_socket, tlv, len, 0) ;

	return 0 ;
}

int handle_client_request(struct client* client) {
	char buf[1024] ;
	int length;
	char* cur ;
	char* bufmax;


	length = recv(client->tcp_socket, buf, 1024, 0) ;
	if (length == 0) {
		return -1 ;
	}
	bufmax = buf + length ;
	trace(LOG_DEBUG, "[%s] Received %d bytes on TCP socket", inet_ntoa(client->tunnel.dest_address),
					 length) ;
	cur = buf ;
	while (cur < bufmax) {
		switch (*cur) {
			case C_CONNECT:
				trace(LOG_INFO, "[%s] Connection asked, negotating parameters", inet_ntoa(client->tunnel.dest_address)) ;
				handle_connect(client) ;
				break ;
			case C_CONNECT_DONE :
				trace(LOG_INFO, "[%s] Connection started", inet_ntoa(client->tunnel.dest_address)) ;
				start_client_tunnel(client) ;
				break;
			case C_KEEPALIVE :
				trace(LOG_DEBUG, "[%s] Received keepalive", inet_ntoa(client->tunnel.dest_address)) ;
				gettimeofday(&(client->tunnel.last_keepalive), NULL);
				break ;
			case C_DISCONNECT :
				trace(LOG_INFO, "[%s] Disconnection asked", inet_ntoa(client->tunnel.dest_address)) ;
				close_tunnel((void*)(&(client->tunnel))) ;
			default :
				trace(LOG_WARNING, "[%s] Unexpected command : %d", inet_ntoa(client->tunnel.dest_address), *cur) ;
		}
		cur++ ;
	}
	return 0 ;
}


