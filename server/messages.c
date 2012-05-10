#include <sys/types.h>
#include <sys/time.h>

#include "tlv.h"
#include "rohc_tunnel.h"

#include "client.h"

#include <syslog.h>
#define MAX_LOG LOG_DEBUG
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)


int handle_connect(struct tunnel* client, struct tunnel_params params)
{
	char tlv[1024] ;
	tlv[0] = C_CONNECT_OK ;
	size_t len = 1 ;
	params.local_address       = client->local_address.s_addr ;

	len += gen_connect(tlv+1, params) ;
	send(client->tcp_socket, tlv, len, 0) ;

	return 0 ;
}

int handle_client_request(struct tunnel* client, struct tunnel_params params) {
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
				handle_connect(client, params) ;
				cur++ ;
				break ;
			case C_CONNECT_DONE :
				trace(LOG_INFO, "[%s] Connection started", inet_ntoa(client->dest_address)) ;
				start_client_tunnel(client) ;
				cur++ ;
				break;
			case C_KEEPALIVE :
				trace(LOG_DEBUG, "[%s] Received keepalive", inet_ntoa(client->dest_address)) ;
				gettimeofday(&(client->last_keepalive), NULL);
				break ;
			case C_DISCONNECT :
				trace(LOG_INFO, "[%s] Disconnection asked", inet_ntoa(client->dest_address)) ;
				close_client(client) ;
			default :
				trace(LOG_WARNING, "[%s] Unexpected command : %d", inet_ntoa(client->dest_address), *cur) ;
		}
	}
	return 0 ;
}


