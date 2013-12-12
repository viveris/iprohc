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

#ifndef IPROHC_SERVER_SERVER_H
#define IPROHC_SERVER_SERVER_H

#include "tlv.h"

#include <stdint.h>
#include <net/if.h>
#include <gnutls/gnutls.h>

/* Structure defining global parameters for the server */
struct server_opts
{
	gnutls_certificate_credentials_t tls_cred;
	gnutls_priority_t priority_cache;

	size_t clients_max_nr;    /**< The maximum number of simultaneous clients */
	int port;
	char pkcs12_f[1024];
	char pidfile_path[1024];
	char basedev[IFNAMSIZ];

	uint32_t local_address;
	size_t netmask;           /**< The length (in bits) of the network mask */

	struct tunnel_params params;
};

#endif

