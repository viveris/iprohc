/*
This file is part of iprohc.

iprohc is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.

iprohc is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with iprohc.  If not, see <http://www.gnu.org/licenses/>.
*/

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
#include "tls.h"

void close_tunnel(void*v_tunnel)
{
	struct tunnel*tunnel = (struct tunnel*) v_tunnel;
	trace(LOG_INFO, "[%s] Properly close client", inet_ntoa(tunnel->dest_address));
	close(tunnel->raw_socket);
	tunnel->alive = -1;  /* Mark to be deleted */
}


int new_client(int socket, int tun, struct client**clients, int max_clients,
               struct server_opts server_opts)
{
	int conn;
	struct   sockaddr_in src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	struct in_addr local;
	int client_id;
	int raw;
	int ret;
	unsigned int verify_status;
	int status = -3;

	/* New client */

	/* Initialize TLS */
	gnutls_session_t session;
	gnutls_init(&session, GNUTLS_SERVER);
	gnutls_priority_set(session, server_opts.priority_cache);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, server_opts.xcred);
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

	/* accept connection */
	conn = accept(socket, (struct sockaddr*)&src_addr, &src_addr_len);
	if(conn < 0)
	{
		trace(LOG_ERR, "failed to accept new connection: %s (%d)",
				strerror(errno), errno);
		status = -3;
		goto error;
	}
	trace(LOG_INFO, "new connection from %s:%d\n", inet_ntoa(src_addr.sin_addr),
			ntohs(src_addr.sin_port));

	/* TLS */
	/* Get rid of warning, it's a "bug" of GnuTLS
	 * (see http://lists.gnu.org/archive/html/help-gnutls/2006-03/msg00020.html) */
	gnutls_transport_set_ptr_nowarn(session, conn);
	do
	{
		ret = gnutls_handshake (session);
	}
	while(ret < 0 && gnutls_error_is_fatal (ret) == 0);

	if(ret < 0)
	{
		trace(LOG_ERR, "TLS handshake failed: %s (%d)", gnutls_strerror(ret), ret);
		status = -3;
		goto tls_deinit;
	}
	trace(LOG_INFO, "TLS handshake succeeded");

	ret = gnutls_certificate_verify_peers2(session, &verify_status);
	if(ret < 0)
	{
		trace(LOG_ERR, "TLS verify failed: %s (%d)", gnutls_strerror(ret), ret);
		status = -3;
		goto tls_deinit;
	}

	if((verify_status & GNUTLS_CERT_INVALID) &&
	   (verify_status != (GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID)))
	{
		trace(LOG_ERR, "Certificate cannot be verified: ");
		if(verify_status & GNUTLS_CERT_REVOKED)
		{
			trace(LOG_ERR, " - Revoked certificate");
		}
		if(verify_status & GNUTLS_CERT_SIGNER_NOT_FOUND)
		{
			trace(LOG_ERR, " - Unable to trust certificate issuer");
		}
		if(verify_status & GNUTLS_CERT_SIGNER_NOT_CA)
		{
			trace(LOG_ERR, " - Certificate issue is not a CA");
		}
		if(verify_status & GNUTLS_CERT_NOT_ACTIVATED)
		{
			trace(LOG_ERR, " - The certificate is not activated");
		}
		if(verify_status & GNUTLS_CERT_EXPIRED)
		{
			trace(LOG_ERR, " - The certificate has expired");
		}
		status = -3;
		goto tls_deinit;
	}

	/* client creation parameters */
	trace(LOG_DEBUG, "Creation of client");

	for(client_id = 0; client_id < max_clients &&
		                clients[client_id] != NULL; client_id++)
	{
	}
	if(client_id == max_clients)
	{
		trace(LOG_ERR, "no more clients accepted, maximum %d reached",
				max_clients);
		status = -2;
		goto tls_deinit;
	}

	clients[client_id] = malloc(sizeof(struct client));
	if(clients[client_id] == NULL)
	{
		trace(LOG_ERR, "failed to allocate memory for new client");
		status = -2;
		goto tls_deinit;
	}
	trace(LOG_DEBUG, "Allocating %p", clients[client_id]);
	clients[client_id]->tcp_socket = conn;
	clients[client_id]->tls_session = session;

	/* dest_addr */
	clients[client_id]->tunnel.dest_address  = src_addr.sin_addr;
	/* local_addr */
	local.s_addr = htonl(ntohl(server_opts.local_address) + client_id + 10);
	clients[client_id]->local_address = local;

	/* set tun */
	clients[client_id]->tunnel.tun = tun;  /* real tun device */
	if(socketpair(AF_UNIX, SOCK_RAW, 0, clients[client_id]->tunnel.fake_tun) < 0)
	{
		trace(LOG_ERR, "failed to create a socket pair for TUN: %s (%d)",
				strerror(errno), errno);
		/* TODO  : Flush */
		status = -1;
		goto reset_tun;
	}

	/* set raw */
	raw = create_raw();
	if(raw < 0)
	{
		trace(LOG_ERR, "Unable to create raw socket");
		status = -1;
		goto close_tun_pair;
	}
	clients[client_id]->tunnel.raw_socket = raw;
	if(socketpair(AF_UNIX, SOCK_RAW, 0, clients[client_id]->tunnel.fake_raw) < 0)
	{
		trace(LOG_ERR, "failed to create a socket pair for the raw socket: "
				"%s (%d)", strerror(errno), errno);
		/* TODO  : Flush */
		status = -1;
		goto close_raw;
	}

	memcpy(&(clients[client_id]->tunnel.params),  &(server_opts.params),
			 sizeof(struct tunnel_params));
	clients[client_id]->tunnel.params.local_address = local.s_addr;
	clients[client_id]->tunnel.alive =   0;
	clients[client_id]->tunnel.close_callback = close_tunnel;
	clients[client_id]->last_keepalive.tv_sec = -1;

	trace(LOG_DEBUG, "Created");

	return client_id;

close_raw:
	clients[client_id]->tunnel.raw_socket = -1;
	close(raw);
close_tun_pair:
	close(clients[client_id]->tunnel.fake_tun[0]);
	clients[client_id]->tunnel.fake_tun[0] = -1;
	close(clients[client_id]->tunnel.fake_tun[1]);
	clients[client_id]->tunnel.fake_tun[1] = -1;
reset_tun:
	clients[client_id]->tunnel.tun = -1;
	free(clients[client_id]);
	clients[client_id] = NULL;
tls_deinit:
	close(conn);
	gnutls_deinit(session);
error:
	return status;
}


int start_client_tunnel(struct client*client)
{
	/* Go threads, go ! */
	pthread_create(&(client->thread_tunnel), NULL, new_tunnel, (void*)(&(client->tunnel)));
	return 0;
}


