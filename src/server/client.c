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
               const int tun,
               const size_t tun_itf_mtu,
               const size_t basedev_mtu,
               struct iprohc_server_session *const client,
               const size_t client_id,
               const struct server_opts server_opts)
{
	char remote_addr_str[INET_ADDRSTRLEN];
	struct in_addr local;
	int raw;
	int ret;
	unsigned int verify_status;
	int status = -1;

	assert(conn >= 0);
	assert(tun >= 0);
	assert(client != NULL);

	/* Initialize TLS */
	gnutls_session_t session;
	gnutls_init(&session, GNUTLS_SERVER);
	gnutls_priority_set(session, server_opts.priority_cache);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, server_opts.xcred);
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

	/* init the debug prefix */
	if(inet_ntop(AF_INET, &(remote_addr.sin_addr), remote_addr_str, INET_ADDRSTRLEN) == NULL)
	{
		trace(LOG_ERR, "failed to convert client address to string: %s (%d)",
		      strerror(errno), errno);
		status = -3;
		goto error;
	}
	trace(LOG_INFO, "[client %s] new connection from %s:%d", remote_addr_str,
	      remote_addr_str, ntohs(remote_addr.sin_port));

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
		trace(LOG_ERR, "[client %s] TLS handshake failed: %s (%d)",
		      remote_addr_str, gnutls_strerror(ret), ret);
		status = -4;
		goto tls_deinit;
	}
	trace(LOG_INFO, "[client %s] TLS handshake succeeded", remote_addr_str);

	ret = gnutls_certificate_verify_peers2(session, &verify_status);
	if(ret < 0)
	{
		trace(LOG_ERR, "[client %s] TLS verify failed: %s (%d)", remote_addr_str,
		      gnutls_strerror(ret), ret);
		status = -5;
		goto tls_deinit;
	}

	if((verify_status & GNUTLS_CERT_INVALID) &&
	   (verify_status != (GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID)))
	{
		trace(LOG_ERR, "[client %s] certificate cannot be verified (status %u)",
		      remote_addr_str, verify_status);
		if(verify_status & GNUTLS_CERT_REVOKED)
		{
			trace(LOG_ERR, "[client %s] - revoked certificate", remote_addr_str);
		}
		if(verify_status & GNUTLS_CERT_SIGNER_NOT_FOUND)
		{
			trace(LOG_ERR, "[client %s] - unable to trust certificate issuer",
			      remote_addr_str);
		}
		if(verify_status & GNUTLS_CERT_SIGNER_NOT_CA)
		{
			trace(LOG_ERR, "[client %s] - certificate issuer is not a CA",
			      remote_addr_str);
		}
		if(verify_status & GNUTLS_CERT_NOT_ACTIVATED)
		{
			trace(LOG_ERR, "[client %s] - the certificate is not activated",
			      remote_addr_str);
		}
		if(verify_status & GNUTLS_CERT_EXPIRED)
		{
			trace(LOG_ERR, "[client %s] - the certificate has expired",
			      remote_addr_str);
		}
		status = -6;
		goto tls_deinit;
	}

	/* client creation parameters */
	trace(LOG_DEBUG, "[client %s] creation of client", remote_addr_str);
	memset(&(client->session.tunnel.stats), 0, sizeof(struct statitics));
	client->session.tcp_socket = conn;
	client->session.tls_session = session;

	/* dest_addr */
	client->session.tunnel.src_address.s_addr = INADDR_ANY;
	client->session.tunnel.dest_address = remote_addr.sin_addr;
	memcpy(client->session.tunnel.dest_addr_str, remote_addr_str, INET_ADDRSTRLEN);

	/* local_addr */
	local.s_addr = htonl(ntohl(server_opts.local_address) + client_id + 10);
	client->session.local_address = local;

	/* set tun */
	client->session.tunnel.tun = tun;  /* real tun device */
	client->session.tunnel.tun_itf_mtu = tun_itf_mtu;
	if(socketpair(AF_UNIX, SOCK_RAW, 0, client->session.tunnel.fake_tun) < 0)
	{
		trace(LOG_ERR, "[client %s] failed to create a socket pair for TUN: "
		      "%s (%d)", remote_addr_str, strerror(errno), errno);
		/* TODO  : Flush */
		status = -8;
		goto reset_tun;
	}

	/* set raw */
	raw = create_raw();
	if(raw < 0)
	{
		trace(LOG_ERR, "[client %s] unable to create raw socket", remote_addr_str);
		status = -9;
		goto close_tun_pair;
	}
	client->session.tunnel.raw_socket = raw;
	client->session.tunnel.basedev_mtu = basedev_mtu;
	if(socketpair(AF_UNIX, SOCK_RAW, 0, client->session.tunnel.fake_raw) < 0)
	{
		trace(LOG_ERR, "[client %s] failed to create a socket pair for the raw "
		      "socket: %s (%d)", remote_addr_str, strerror(errno), errno);
		/* TODO  : Flush */
		status = -10;
		goto close_raw;
	}

	memcpy(&(client->session.tunnel.params),  &(server_opts.params),
			 sizeof(struct tunnel_params));
	client->session.tunnel.params.local_address = local.s_addr;
	client->session.status = IPROHC_SESSION_CONNECTING;
	client->session.last_keepalive.tv_sec = -1;

	ret = pthread_mutex_init(&(client->session.status_lock), NULL);
	if(ret != 0)
	{
		trace(LOG_ERR, "[client %s] failed to init lock: %s (%d)",
		      remote_addr_str, strerror(ret), ret);
		status = -11;
		goto close_raw_pair;
	}
	ret = pthread_mutex_init(&(client->session.client_lock), NULL);
	if(ret != 0)
	{
		trace(LOG_ERR, "[client %s] failed to init client_lock: %s (%d)",
		      remote_addr_str, strerror(ret), ret);
		status = -12;
		goto destroy_lock;
	}

	trace(LOG_DEBUG, "[client %s] client context created", remote_addr_str);

	client->is_init = true;
	return client_id;

destroy_lock:
	pthread_mutex_destroy(&(client->session.status_lock));
close_raw_pair:
	close(client->session.tunnel.fake_raw[0]);
	client->session.tunnel.fake_raw[0] = -1;
	close(client->session.tunnel.fake_raw[1]);
	client->session.tunnel.fake_raw[1] = -1;
close_raw:
	client->session.tunnel.raw_socket = -1;
	close(raw);
close_tun_pair:
	close(client->session.tunnel.fake_tun[0]);
	client->session.tunnel.fake_tun[0] = -1;
	close(client->session.tunnel.fake_tun[1]);
	client->session.tunnel.fake_tun[1] = -1;
reset_tun:
	client->session.tunnel.tun = -1;
	client->is_init = false;
tls_deinit:
	gnutls_deinit(session);
error:
	return status;
}


void del_client(struct iprohc_server_session *const client)
{
	assert(client != NULL);

	trace(LOG_INFO, "[client %s] remove client", client->session.tunnel.dest_addr_str);

	free(client->session.tunnel.stats.stats_packing);

	/* reset source and destination addresses */
	memset(&(client->session.tunnel.dest_address), 0, sizeof(struct in_addr));
	memset(&(client->session.tunnel.dest_addr_str), 0, INET_ADDRSTRLEN);
	memset(&(client->session.tunnel.src_address), 0, sizeof(struct in_addr));

	pthread_mutex_destroy(&client->session.client_lock);
	pthread_mutex_destroy(&client->session.status_lock);

	/* close RAW socket pair */
	close(client->session.tunnel.fake_raw[0]);
	client->session.tunnel.fake_raw[0] = -1;
	close(client->session.tunnel.fake_raw[1]);
	client->session.tunnel.fake_raw[1] = -1;

	/* close RAW socket (nothing to do if close_tunnel() was already called) */
	close(client->session.tunnel.raw_socket);
	client->session.tunnel.raw_socket = -1;

	/* close TUN socket pair */
	close(client->session.tunnel.fake_tun[0]);
	client->session.tunnel.fake_tun[0] = -1;
	close(client->session.tunnel.fake_tun[1]);
	client->session.tunnel.fake_tun[1] = -1;

	/* reset TUN fd (do not close it, it is shared with other clients) */
	client->session.tunnel.tun = -1;

	/* close TCP socket */
	close(client->session.tcp_socket);
	client->session.tcp_socket = -1;

	/* free TLS resources */
	gnutls_deinit(client->session.tls_session);
	
	/* free client context */
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
	assert(client->session.tunnel.raw_socket != -1);

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

