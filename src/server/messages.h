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

#include "client.h"
#include "rohc_tunnel.h"


/** Print in logs a trace related to the given client */
#define client_trace(client, prio, format, ...) \
	do \
	{ \
		trace((prio), "[client %s] " format, \
		      (client)->tunnel.dest_addr_str, ##__VA_ARGS__); \
	} \
	while(0)


int handle_client_request(struct client*client);
