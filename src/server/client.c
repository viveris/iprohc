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


#include "tun_helpers.h"
#include "rohc_tunnel.h"
#include "client.h"
#include "messages.h"
#include "tls.h"
#include "log.h"

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
	int status = -1;

	assert(conn >= 0);
	assert(raw >= 0);
	assert(tun >= 0);
	assert(client != NULL);

	client_local_addr.s_addr =
		htonl(ntohl(server_opts.local_address) + 1 + client_id);

	/* init the generic session part */
	if(!iprohc_session_new(&(client->session), NULL, handle_client_request, NULL, NULL,
	                       GNUTLS_SERVER, server_opts.tls_cred,
	                       server_opts.priority_cache, conn, client_local_addr,
	                       remote_addr, raw, tun, server_opts.params.keepalive_timeout))
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

	/* init tunnel context */
	if(!iprohc_tunnel_new(&(client->session.tunnel), server_opts.params,
	                      client->session.local_address.s_addr,
	                      client->fake_raw[0], client->fake_tun[0],
	                      basedev_mtu, tun_itf_mtu))
	{
		trace(LOG_ERR, "[client %s] failed to init tunnel context",
		      client->session.dst_addr_str);
		goto close_raw_pair;
	}
	client->session.tunnel.tun_fd_out = tun;
	client->session.tunnel.raw_socket_out = raw;

	trace(LOG_DEBUG, "[client %s] client context created",
	      client->session.dst_addr_str);

	/* tell everybody that this client is now initialized */
	AO_store_release_write(&(client->is_init), 1);

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

	if(!iprohc_tunnel_free(&(client->session.tunnel)))
	{
		trace(LOG_ERR, "[client %s] failed to reset tunnel context",
		      client->session.dst_addr_str);
	}

	/* close RAW socket pair */
	close(client->fake_raw[0]);
	client->fake_raw[0] = -1;
	close(client->fake_raw[1]);
	client->fake_raw[1] = -1;

	/* close TUN socket pair */
	close(client->fake_tun[0]);
	client->fake_tun[0] = -1;
	close(client->fake_tun[1]);
	client->fake_tun[1] = -1;

	if(!iprohc_session_free(&(client->session)))
	{
		trace(LOG_ERR, "failed to reset session for client");
	}

	client->is_init = false;
}

