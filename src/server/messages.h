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

#include "server_session.h"

/** Print in logs a trace related to the given session */
#define session_trace(session, prio, format, ...) \
	do \
	{ \
		trace((prio), "[client %s] " format, \
		      (session)->dst_addr_str, ##__VA_ARGS__); \
	} \
	while(0)


bool handle_client_request(struct iprohc_session *const session,
                           const uint8_t *const msg,
                           const size_t len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

