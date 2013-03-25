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

/* rohc_tunnel.h -- Functions handling a tunnel, client or server-side
*/
#ifndef ROHC_IPIP_TUNNEL_H
#define ROHC_IPIP_TUNNEL_H

#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>

#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>

#include "tlv.h"


struct statitics {
	int decomp_failed;
	int decomp_total;

	int comp_failed;
	int comp_total;

	int head_comp_size;
	int head_uncomp_size;

	int total_comp_size;
	int total_uncomp_size;

	int unpack_failed;
	int total_received;

	int*stats_packing;
	int n_stats_packing;
};


/* Stucture defining a tunnel */
struct tunnel {
	struct in_addr dest_address;
	struct in_addr src_address;

	int raw_socket /* Real RAW */;
	int fake_raw[2];   /* Fake RAW device for server side */

	int tun;   /* Real TUN device */
	int fake_tun[2];   /* Fake TUN device for server side */

	char alive;
	struct timeval last_keepalive;

	struct tunnel_params params;

	struct statitics stats;
};

/* Called in a thread on a new tunnel */
void * new_tunnel(void*arg);

#endif

