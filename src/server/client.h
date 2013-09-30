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

#ifndef IPROHC_SERVER_CLIENT_H
#define IPROHC_SERVER_CLIENT_H

#include <time.h>

#include "rohc_tunnel.h"
#include "tlv.h"

#include "server.h"

struct client {
	int tcp_socket;
	gnutls_session_t tls_session;
	struct in_addr local_address;

	pthread_t thread_tunnel;
	struct tunnel tunnel;

	struct timeval last_keepalive;

	int packing;
};

int new_client(int socket,
               int tun,
               const size_t tun_itf_mtu,
               const size_t basedev_mtu,
               struct client**clients,
               size_t *const clients_nr,
               const size_t max_clients,
               struct server_opts server_opts);

void del_client(struct client *const client,
                size_t *const clients_nr,
                const size_t max_clients)
	__attribute__((nonnull(1, 2)));

int  start_client_tunnel(struct client*client);
void stop_client_tunnel(struct client *const client)
	__attribute__((nonnull(1)));

#endif

