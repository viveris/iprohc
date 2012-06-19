#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <string.h>

#include "log.h"

#include "tun_helpers.h"
#include "rohc_tunnel.h"
#include "client.h"

void close_tunnel(void* v_tunnel)
{
	struct tunnel* tunnel = (struct tunnel*) v_tunnel ;
	trace(LOG_INFO, "[%s] Properly close client", inet_ntoa(tunnel->dest_address)) ;
	close(tunnel->raw_socket) ;
	tunnel->alive = -1 ; /* Mark to be deleted */
}

int new_client(int socket, int tun, struct client** clients, int max_clients, struct server_opts server_opts) {
	int conn; 
	struct	sockaddr_in src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	struct in_addr local;
	int i = 0 ;
	int raw ;
	int ret ;
	unsigned int verify_status ;

	/* New client */

	/* Initialize TLS */
	gnutls_session_t session;
	gnutls_init(&session, GNUTLS_SERVER);
	gnutls_priority_set(session, server_opts.priority_cache);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, server_opts.xcred) ;
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

	/* accept connection */
	conn = accept(socket, (struct sockaddr*)&src_addr, &src_addr_len) ;
	if (conn < 0) {
		perror("Fail accept\n") ;
	}
	trace(LOG_INFO, "Connection from %s (%d)\n", inet_ntoa(src_addr.sin_addr), src_addr.sin_addr.s_addr) ;

	/* TLS */
	/* Get rid of warning, it's a "bug" of GnuTLS (cf http://lists.gnu.org/archive/html/help-gnutls/2006-03/msg00020.html) */
	#if defined __GNUC__
	#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
	#endif
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) conn);
	#if defined __GNUC__
	#pragma GCC diagnostic error "-Wint-to-pointer-cast"
	#endif
	do {
	  ret = gnutls_handshake (session);
	} while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if (ret < 0) {
		close(conn);
		gnutls_deinit(session);
		trace(LOG_ERR, "TLS handshake failed : %s", gnutls_strerror(ret)) ;
		return -3 ;
	}
	trace(LOG_INFO, "TLS handshake succeeded") ;
	
	ret = gnutls_certificate_verify_peers2(session, &verify_status) ;
	if (ret < 0) {
		trace(LOG_ERR, "TLS verify failed : %s", gnutls_strerror(ret)) ;
		return -3 ;
	}

	if  (verify_status & GNUTLS_CERT_INVALID
     && (verify_status != (GNUTLS_CERT_INSECURE_ALGORITHM|GNUTLS_CERT_INVALID))
		) {
		trace(LOG_ERR, "Certificate can't be verified : ") ;
		if (verify_status & GNUTLS_CERT_REVOKED)
			trace(LOG_ERR, " - Revoked certificate") ;
		if (verify_status & GNUTLS_CERT_SIGNER_NOT_FOUND)
			trace(LOG_ERR, " - Unable to trust certificate issuer") ;
		if (verify_status & GNUTLS_CERT_SIGNER_NOT_CA)
			trace(LOG_ERR, " - Certificate issue is not a CA") ;
		if (verify_status & GNUTLS_CERT_NOT_ACTIVATED)
			trace(LOG_ERR, " - The certificate is not activated") ;
		if (verify_status & GNUTLS_CERT_EXPIRED)
			trace(LOG_ERR, " - The certificate has expired") ;
		return -3 ;
	}

	/* client creation parameters */
	trace(LOG_DEBUG, "Creation of client") ;
	
	while (clients[i] != NULL && i < max_clients) { i++; }
	if (i == max_clients) {
		return -2 ;
	}

	clients[i] = malloc(sizeof(struct client)) ;
	trace(LOG_DEBUG, "Allocating %p", clients[i]) ;
	clients[i]->tcp_socket = conn ;
	clients[i]->tls_session = session ;

	/* dest_addr */
	clients[i]->tunnel.dest_address  = src_addr.sin_addr ;
	/* local_addr */
	local.s_addr = htonl(ntohl(server_opts.local_address) + i + 10) ;
	clients[i]->local_address = local ;

	/* set tun */
	clients[i]->tunnel.tun = tun ; /* real tun device */
	if (socketpair(AF_UNIX, SOCK_RAW, 0, clients[i]->tunnel.fake_tun) < 0) {
		perror("Can't open pipe for tun") ;
		/* TODO  : Flush */
		return 1 ;
	}

	/* set raw */
	raw = create_raw() ;
	if (raw < 0) {
		trace(LOG_ERR, "Unable to create raw socket") ;
	}
	clients[i]->tunnel.raw_socket = raw ;
	if (socketpair(AF_UNIX, SOCK_RAW, 0, clients[i]->tunnel.fake_raw) < 0) {
		perror("Can't open pipe for raw") ;
		/* TODO  : Flush */
		return -1 ;
	}

	memcpy(&(clients[i]->tunnel.params),  &(server_opts.params), sizeof(struct tunnel_params)) ;
	clients[i]->tunnel.params.local_address = local.s_addr ;
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


