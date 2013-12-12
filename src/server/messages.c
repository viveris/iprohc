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

#include <sys/types.h>
#include <sys/time.h>
#include <assert.h>

#include "tlv.h"
#include "rohc_tunnel.h"

#include "client.h"

#include "log.h"

bool handle_connect(struct client *const client,
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

	assert(client != NULL);
	assert(message != NULL);
	assert(parsed_len != NULL);

	*parsed_len = 0;
	tlv_len = 0;

	client_tracep(client, LOG_INFO, "connection asked, negotating parameters");

	/* parse connect message received from client */
	is_ok = parse_connrequest(message, message_len, parsed_len, &packing,
	                          &client_proto_version);
	if(!is_ok)
	{
		client_tracep(client, LOG_ERR, "unable to parse connection request");

		/* create failure answer for client */
		tlv[0] = C_CONNECT_KO;
		tlv_len++;
		// TODO : Clear client
	}
	else if(client_proto_version != CURRENT_PROTO_VERSION)
	{
		/* Current behaviour as for proto version = 1 : refuse any other version */
		client_tracep(client, LOG_WARNING, "connection refused because of wrong "
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

		client_tracep(client, LOG_INFO, "connection asked, negotating parameters "
		              "(proto version = %d, asked packing = %d)",
		              client_proto_version, packing);
		client->packing = packing;

		/* create successful answer for client */
		tlv[0] = C_CONNECT_OK;
		tlv_len++;

		/* add parameters in TLV format */
		is_ok = gen_connect(client->tunnel.params, tlv + 1, &len);
		if(!is_ok)
		{
			client_tracep(client, LOG_ERR, "failed to generate the connect "
			              "message for client");
			goto error;
		}
		tlv_len += len;

		is_success = true;
	}

	gnutls_record_send(client->tls_session, tlv, tlv_len);

	return is_success;

error:
	return false;
}


int handle_client_request(struct client *const client)
{
	unsigned char buf[1024];
	int length;
	unsigned char *remain_data;
	size_t remain_len;;
	bool is_ok;

	length = gnutls_record_recv(client->tls_session, buf, 1024);
	if(length == 0)
	{
		return -1;
	}
	if(length < 0)
	{
		return -1;
	}
	client_tracep(client, LOG_DEBUG, "received %d bytes on TCP socket",
	              length);

	remain_data = buf;
	remain_len = length;
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

				client_tracep(client, LOG_INFO, "connection request from client");
				is_ok = handle_connect(client, remain_data, remain_len, &parsed_len);
				if(!is_ok)
				{
					return -1;
				}
				remain_data += parsed_len;
				remain_len -= parsed_len;
				break;
			}
			case C_CONNECT_DONE:
				client_tracep(client, LOG_INFO, "connection started by client");
				if(start_client_tunnel(client) < 0)
				{
					return -1;
				}
				break;
			case C_KEEPALIVE:
				client_tracep(client, LOG_DEBUG, "received keepalive from client");
				break;
			case C_DISCONNECT:
				client_tracep(client, LOG_INFO, "disconnection asked by client");
				stop_client_tunnel(client);
				break;
			default:
				client_tracep(client, LOG_WARNING, "unexpected command 0x%02x "
				              "received from client", req_type);
				return -1;
		}
	}

	return 0;
}

