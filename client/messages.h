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

#include "rohc_tunnel.h"
#include "tlv.h"

#include <gnutls/gnutls.h>

/* Structure defining the options
   needed for tunnel creation
*/
struct client_opts {
	int socket;
	gnutls_session_t tls_session;

	char *tun_name;
	char *up_script_path;

	int packing;
};

/* Generic functions for handling messages */
int handle_message(struct tunnel*tunnel, char*buf, int length, struct client_opts opts);

/* Handlers of differents messages types */
char * handle_okconnect(struct tunnel*tunnel, char*tlv, struct client_opts opts);


