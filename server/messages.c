#include <sys/types.h>
#include <sys/time.h>

#include "tlv.h"
#include "rohc_tunnel.h"

#include "client.h"

#include "log.h"

char* handle_connect(struct client* client, char* buf)
{

	trace(LOG_INFO, "[%s] Connection asked, negotating parameters", inet_ntoa(client->tunnel.dest_address)) ;
	/* Receiving parameters */
	char* newbuf ;
	int packing ;
	int client_proto_version ;

	/* Prepare order for connection */
	char tlv[1024] ;
	size_t len = 1 ;

	newbuf = parse_connrequest(buf, &packing, &client_proto_version) ;
	if (newbuf == NULL) {
		trace(LOG_ERR, "Unable to parse connection request") ;
			tlv[0] = C_CONNECT_KO ;
			// TODO : Clear client
	} else {
		if (client_proto_version != CURRENT_PROTO_VERSION) {
			/* Current behaviour as for proto version = 1 : refuse any other version */
			trace(LOG_WARNING, "[%s] Connection refused because of wrong protocol version", inet_ntoa(client->tunnel.dest_address)) ;
			tlv[0] = C_CONNECT_KO ;
			// TODO : Clear client
		} else {
			trace(LOG_INFO, "[%s] Connection asked, negotating parameters (proto version %d, asked packing : %d)", inet_ntoa(client->tunnel.dest_address), client_proto_version, packing) ;
			client->packing = packing ;
			tlv[0] = C_CONNECT_OK ;
		}
	}

	len += gen_connect(tlv+1, client->tunnel.params) ;
	gnutls_record_send(client->tls_session, tlv, len) ;

	return newbuf ;
}

int handle_client_request(struct client* client) {
	char buf[1024] ;
	int length;
	char* cur ;
	char* bufmax;

	length = gnutls_record_recv(client->tls_session, buf, 1024) ;
	if (length == 0) {
		return -1 ;
	}
	bufmax = buf + length ;
	trace(LOG_DEBUG, "[%s] Received %d bytes on TCP socket", inet_ntoa(client->tunnel.dest_address),
					 length) ;
	if (length < 0) {
		return -1;
	}

	cur = buf ;
	while (cur < bufmax) {
		switch (*cur) {
			case C_CONNECT:
				if (++cur >= bufmax) {
					return -1;
				}

				cur = handle_connect(client, cur) ;
				
				if (cur == NULL) {
					return -1 ;
				}
				break ;
			case C_CONNECT_DONE :
				trace(LOG_INFO, "[%s] Connection started", inet_ntoa(client->tunnel.dest_address)) ;
				start_client_tunnel(client) ;
				cur++ ;
				break;
			case C_KEEPALIVE :
				trace(LOG_DEBUG, "[%s] Received keepalive", inet_ntoa(client->tunnel.dest_address)) ;
				gettimeofday(&(client->tunnel.last_keepalive), NULL);
				cur++ ;
				break ;
			case C_DISCONNECT :
				trace(LOG_INFO, "[%s] Disconnection asked", inet_ntoa(client->tunnel.dest_address)) ;
				close_tunnel((void*)(&(client->tunnel))) ;
				cur++ ;
				break ;
			default :
				trace(LOG_WARNING, "[%s] Unexpected command : %d", inet_ntoa(client->tunnel.dest_address), *cur) ;
				cur++ ;
		}
	}
	return 0 ;
}


