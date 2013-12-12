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

#include "tlv.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>

#include <gnutls/gnutls.h>

#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>


/// The maximal size of data that can be received on the virtual interface
#define TUNTAP_BUFSIZE 1518

struct statitics
{
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

	int *stats_packing;
	int n_stats_packing;
};


/* Stucture defining a tunnel */
struct iprohc_tunnel
{
	bool is_init; /**< Whether the tunnel is defined or not */

	/* input and output RAW sockets may be different sockets */
	int raw_socket_in;   /**< The RAW socket for receiving data from remote endpoint */
	int raw_socket_out;  /**< The RAW socket towards the remote endpoint */

	/* input and output TUN fds may be different fds */
	int tun_fd_in;       /**< The TUN device for receiving data from local endpoint */
	int tun_fd_out;      /**< The TUN device for towards the local endpoint */
	
	size_t basedev_mtu;  /**< The MTU (in bytes) of the base interface */
	size_t tun_itf_mtu;  /**< The MTU (in bytes) of the TUN interface */

	/* ROHC */
	struct rohc_comp *comp;      /**< The ROHC compressor */
	struct rohc_decomp *decomp;  /**< The ROHC decompressor */

	/** The frame being packed, stored in context until completion or timeout */
	unsigned char packing_frame[TUNTAP_BUFSIZE];

	struct tunnel_params params;

	struct statitics stats;
};


bool iprohc_tunnel_new(struct iprohc_tunnel *const tunnel,
                       const struct tunnel_params params,
                       const uint32_t local_addr,
                       const int raw_socket,
                       const int tun_fd,
                       const size_t base_dev_mtu,
                       const size_t tun_dev_mtu)
	__attribute__((warn_unused_result, nonnull(1)));

bool iprohc_tunnel_free(struct iprohc_tunnel *const tunnel)
	__attribute__((warn_unused_result, nonnull(1)));

void * iprohc_tunnel_run(void *arg);

#endif

