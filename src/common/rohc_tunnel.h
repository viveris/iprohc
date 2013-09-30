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

#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>

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


typedef enum
{
	IPROHC_TUNNEL_PENDING_DELETE  = 0,
	IPROHC_TUNNEL_CONNECTING      = 1,
	IPROHC_TUNNEL_CONNECTED       = 2,
} iprohc_tunnel_status_t;


/* Stucture defining a tunnel */
struct tunnel
{
	struct in_addr dest_address;
	char dest_addr_str[INET_ADDRSTRLEN];
	struct in_addr src_address;

	int raw_socket /* Real RAW */;
	size_t basedev_mtu;  /**< The MTU (in bytes) of the base interface */
	int fake_raw[2];   /* Fake RAW device for server side */

	int tun;   /* Real TUN device */
	size_t tun_itf_mtu;  /**< The MTU (in bytes) of the TUN interface */
	int fake_tun[2];   /* Fake TUN device for server side */

	iprohc_tunnel_status_t status;
	struct timeval last_keepalive;

	struct tunnel_params params;

	struct statitics stats;
};

/* Called in a thread on a new tunnel */
void * new_tunnel(void*arg);

#endif

