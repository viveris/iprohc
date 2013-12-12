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

#include "server_session.h"
#include "server.h"

int new_client(const int conn,
               const struct sockaddr_in remote_addr,
               const int raw,
               const int tun,
               const size_t tun_itf_mtu,
               const size_t basedev_mtu,
               struct iprohc_server_session *const client,
               const size_t client_id,
               const struct server_opts server_opts);

void del_client(struct iprohc_server_session *const client)
	__attribute__((nonnull(1)));

int  start_client_tunnel(struct iprohc_server_session *const client);

void stop_client_tunnel(struct iprohc_server_session *const client)
	__attribute__((nonnull(1)));

#endif

