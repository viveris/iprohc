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

#include "messages.h"
#include "client.h"
#include "log.h"

#include <sys/types.h>
#include <sys/time.h>
#include <assert.h>


static bool handle_connect(struct iprohc_session *const session,
                           const unsigned char *const message,
                           const size_t message_len,
                           size_t *const parsed_len)
	__attribute__((warn_unused_result, nonnull(1, 2, 4)));


bool handle_client_request(struct iprohc_session *const session,
                           const uint8_t *const msg,
                           const size_t len)
{
	const unsigned char *remain_data;
	size_t remain_len;
	bool is_ok;

	remain_data = msg;
	remain_len = len;
	while(remain_len > 0)
	{
		uint8_t req_type;

		req_type = remain_data[0];
		remain_data++;
		remain_len--;

		switch(req_type)
		{
			case C_CONNECT:
			{
				size_t parsed_len;

				session_trace(session, LOG_INFO, "connection request received from client");
				is_ok = handle_connect(session, remain_data, remain_len, &parsed_len);
				if(!is_ok)
				{
					goto error;
				}
				remain_data += parsed_len;
				remain_len -= parsed_len;
				break;
			}
			case C_CONNECT_DONE:
				session_trace(session, LOG_INFO, "client fully established session");
				session->status = IPROHC_SESSION_CONNECTED;
				break;
			case C_KEEPALIVE:
				session_trace(session, LOG_DEBUG, "keepalive received from client");
				break;
			case C_DISCONNECT:
				session_trace(session, LOG_INFO, "disconnection asked by client");
				session->status = IPROHC_SESSION_PENDING_DELETE;
				break;
			default:
				session_trace(session, LOG_WARNING, "unexpected command 0x%02x "
				               "received from client", req_type);
				goto error;
		}
	}

	return true;

error:
	return false;
}


static bool handle_connect(struct iprohc_session *const session,
                           const unsigned char *const message,
                           const size_t message_len,
                           size_t *const parsed_len)
{
	/* Receiving parameters */
	int packing;
	int client_proto_version;

	/* Prepare order for connection */
	unsigned char tlv[1024];
	size_t tlv_len;

	bool is_ok;
	bool is_success = false;

	assert(session != NULL);
	assert(message != NULL);
	assert(parsed_len != NULL);

	*parsed_len = 0;
	tlv_len = 0;

	session_trace(session, LOG_INFO, "connection asked, negotating parameters");

	/* parse connect message received from client */
	is_ok = parse_connrequest(message, message_len, parsed_len, &packing,
	                          &client_proto_version);
	if(!is_ok)
	{
		session_trace(session, LOG_ERR, "unable to parse connection request");

		/* create failure answer for client */
		tlv[0] = C_CONNECT_KO;
		tlv_len++;
		// TODO : Clear client
	}
	else if(client_proto_version != CURRENT_PROTO_VERSION)
	{
		/* Current behaviour as for proto version = 1 : refuse any other version */
		session_trace(session, LOG_WARNING, "connection refused because of wrong "
		              "protocol version: %d received from client but %d expected",
		              client_proto_version, CURRENT_PROTO_VERSION);

		/* create failure answer for client */
		tlv[0] = C_CONNECT_KO;
		tlv_len++;
		// TODO : Clear client
	}
	else
	{
		size_t len;

		session_trace(session, LOG_INFO, "connection asked, negotating parameters "
		              "(proto version = %d, asked packing = %d)",
		              client_proto_version, packing);
		if(packing < 0 || packing > 10)
		{
			/* invalid packing value requested by client, don't use it */
			session_trace(session, LOG_NOTICE, "ignore invalid packing level "
			              "requested by client");
		}
		else if(packing != 0)
		{
			session_trace(session, LOG_INFO, "client asked for packing level %d",
			              packing);
			session->tunnel.params.packing = packing;
		}

		/* create successful answer for client */
		tlv[0] = C_CONNECT_OK;
		tlv_len++;

		/* add parameters in TLV format */
		is_ok = gen_connect(session->tunnel.params, tlv + 1, &len);
		if(!is_ok)
		{
			session_trace(session, LOG_ERR, "failed to generate the connect "
			              "message for client");
			goto error;
		}
		tlv_len += len;

		is_success = true;
	}

	gnutls_record_send(session->tls_session, tlv, tlv_len);

	return is_success;

error:
	return false;
}


