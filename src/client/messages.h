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

#include "client_session.h"
#include "tlv.h"

#include <gnutls/gnutls.h>

/* Generic functions for handling messages */
bool handle_message(struct iprohc_client_session *const client_session,
						  unsigned char *const buf,
						  const int length)
	__attribute__((nonnull(1, 2), warn_unused_result));

bool client_send_disconnect_msg(gnutls_session_t session)
	__attribute__((warn_unused_result));

