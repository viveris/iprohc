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
#include <assert.h>
#include <signal.h>

#include "log.h"

#include "tun_helpers.h"
#include "rohc_tunnel.h"
#include "client.h"
#include "tls.h"


int new_client(const int conn,
               const struct sockaddr_in remote_addr,
               const int raw,
               const int tun,
               const size_t tun_itf_mtu,
               const size_t basedev_mtu,
               struct iprohc_server_session *const client,
               const size_t client_id,
               const struct server_opts server_opts)
{
	struct in_addr client_local_addr;
	unsigned int verify_status;
	int status = -1;
	int ret;

	assert(conn >= 0);
	assert(raw >= 0);
	assert(tun >= 0);
	assert(client != NULL);

	client_local_addr.s_addr =
		htonl(ntohl(server_opts.local_address) + 1 + client_id);

	/* init the generic session part */
	if(!iprohc_session_new(&(client->session), GNUTLS_SERVER, server_opts.tls_cred,
	                       server_opts.priority_cache, conn, client_local_addr,
	                       remote_addr, raw, tun, basedev_mtu, tun_itf_mtu))
	{
		trace(LOG_ERR, "failed to init session for client #%zu", client_id);
		status = -1;
		goto error;
	}

	/* create a socket pair for the TUN device between the route thread and
	 * the client thread */
	if(socketpair(AF_UNIX, SOCK_RAW, 0, client->fake_tun) < 0)
	{
		trace(LOG_ERR, "[client %s] failed to create a socket pair for TUN: "
		      "%s (%d)", client->session.dst_addr_str, strerror(errno), errno);
		status = -2;
		goto free_session;
	}
	/* for local input, don't use the real TUN fd, but the socket pair */
	client->session.tunnel.tun_fd_in = client->fake_tun[0];

	/* create a socket pair for the RAW socket between the route thread and
	 * the client thread */
	if(socketpair(AF_UNIX, SOCK_RAW, 0, client->fake_raw) < 0)
	{
		trace(LOG_ERR, "[client %s] failed to create a socket pair for the raw "
		      "socket: %s (%d)", client->session.dst_addr_str, strerror(errno),
		      errno);
		status = -3;
		goto close_tun_pair;
	}
	/* for remote input, don't use the real RAW fd, but the socket pair */
	client->session.tunnel.raw_socket_in = client->fake_raw[0];

	/* set tunnel paramaters with the ones retrieved in configuration */
	memcpy(&(client->session.tunnel.params), &server_opts.params,
	       sizeof(struct tunnel_params));
	client->session.tunnel.params.local_address =
		client->session.local_address.s_addr;

	/* Get rid of warning, it's a "bug" of GnuTLS
	 * (see http://lists.gnu.org/archive/html/help-gnutls/2006-03/msg00020.html) */
	gnutls_transport_set_ptr_nowarn(client->session.tls_session, conn);

	/* perform TLS handshake */
	do
	{
		ret = gnutls_handshake(client->session.tls_session);
	}
	while(ret < 0 && gnutls_error_is_fatal (ret) == 0);
	if(ret < 0)
	{
		trace(LOG_ERR, "[client %s] TLS handshake failed: %s (%d)",
		      client->session.dst_addr_str, gnutls_strerror(ret), ret);
		status = -4;
		goto close_raw_pair;
	}
	trace(LOG_INFO, "[client %s] TLS handshake succeeded",
	      client->session.dst_addr_str);

	/* check the peer certificate */
	ret = gnutls_certificate_verify_peers2(client->session.tls_session, &verify_status);
	if(ret < 0)
	{
		trace(LOG_ERR, "[client %s] TLS verify failed: %s (%d)",
		      client->session.dst_addr_str, gnutls_strerror(ret), ret);
		status = -5;
		goto close_raw_pair;
	}

	if((verify_status & GNUTLS_CERT_INVALID) &&
	   (verify_status != (GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID)))
	{
		trace(LOG_ERR, "[client %s] certificate cannot be verified (status %u)",
		      client->session.dst_addr_str, verify_status);
		if(verify_status & GNUTLS_CERT_REVOKED)
		{
			trace(LOG_ERR, "[client %s] - revoked certificate",
			      client->session.dst_addr_str);
		}
		if(verify_status & GNUTLS_CERT_SIGNER_NOT_FOUND)
		{
			trace(LOG_ERR, "[client %s] - unable to trust certificate issuer",
			      client->session.dst_addr_str);
		}
		if(verify_status & GNUTLS_CERT_SIGNER_NOT_CA)
		{
			trace(LOG_ERR, "[client %s] - certificate issuer is not a CA",
			      client->session.dst_addr_str);
		}
		if(verify_status & GNUTLS_CERT_NOT_ACTIVATED)
		{
			trace(LOG_ERR, "[client %s] - the certificate is not activated",
			      client->session.dst_addr_str);
		}
		if(verify_status & GNUTLS_CERT_EXPIRED)
		{
			trace(LOG_ERR, "[client %s] - the certificate has expired",
			      client->session.dst_addr_str);
		}
		status = -6;
		goto close_raw_pair;
	}

	trace(LOG_DEBUG, "[client %s] client context created",
	      client->session.dst_addr_str);

	client->is_init = true;
	return client_id;

close_raw_pair:
	close(client->fake_raw[0]);
	client->fake_raw[0] = -1;
	close(client->fake_raw[1]);
	client->fake_raw[1] = -1;
close_tun_pair:
	close(client->fake_tun[0]);
	client->fake_tun[0] = -1;
	close(client->fake_tun[1]);
	client->fake_tun[1] = -1;
free_session:
	if(!iprohc_session_free(&(client->session)))
	{
		trace(LOG_ERR, "failed to reset session for client #%zu", client_id);
	}
error:
	return status;
}


void del_client(struct iprohc_server_session *const client)
{
	assert(client != NULL);
	assert(client->is_init);

	trace(LOG_INFO, "[client %s] remove client", client->session.dst_addr_str);

	free(client->session.tunnel.stats.stats_packing);

	/* close RAW socket pair */
	close(client->fake_raw[0]);
	client->fake_raw[0] = -1;
	close(client->fake_raw[1]);
	client->fake_raw[1] = -1;

	/* reset RAW socket (do not close it, it is shared with other clients) */
	client->session.tunnel.raw_socket_in = -1;
	client->session.tunnel.raw_socket_out = -1;

	/* close TUN socket pair */
	close(client->fake_tun[0]);
	client->fake_tun[0] = -1;
	close(client->fake_tun[1]);
	client->fake_tun[1] = -1;

	/* reset TUN fd (do not close it, it is shared with other clients) */
	client->session.tunnel.tun_fd_in = -1;
	client->session.tunnel.tun_fd_out = -1;

	if(!iprohc_session_free(&(client->session)))
	{
		trace(LOG_ERR, "failed to reset session for client");
	}

	client->is_init = false;
}


int start_client_tunnel(struct iprohc_server_session *const client)
{
	int ret;

	/* Go threads, go ! */
	ret = pthread_create(&(client->session.thread_tunnel), NULL, new_tunnel,
	                     &(client->session));
	if(ret != 0)
	{
		trace(LOG_ERR, "failed to create the client tunnel thread: %s (%d)",
		      strerror(ret), ret);
		return -1;
	}

	return 0;
}

void stop_client_tunnel(struct iprohc_server_session *const client)
{
	int ret;

	assert(client != NULL);

	ret = pthread_mutex_lock(&client->session.status_lock);
	if(ret != 0)
	{
		trace(LOG_ERR, "stop_client_tunnel: failed to acquire lock for client");
		assert(0);
		goto error;
	}

	client->session.status = IPROHC_SESSION_PENDING_DELETE;  /* Mark to be deleted */

	ret = pthread_mutex_unlock(&client->session.status_lock);
	if(ret != 0)
	{
		trace(LOG_ERR, "stop_client_tunnel: failed to release lock for client");
		assert(0);
		goto error;
	}

	trace(LOG_INFO, "wait for client thread to stop");
	pthread_kill(client->session.thread_tunnel, SIGHUP);
	pthread_join(client->session.thread_tunnel, NULL);

error:
	;
}

