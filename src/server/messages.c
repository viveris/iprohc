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

	assert(client != NULL);
	assert(message != NULL);
	assert(parsed_len != NULL);

	*parsed_len = 0;
	tlv_len = 0;

	trace(LOG_INFO, "[%s] Connection asked, negotating parameters",
	      inet_ntoa(client->tunnel.dest_address));

	/* parse connect message received from client */
	is_ok = parse_connrequest(message, message_len, parsed_len, &packing,
	                          &client_proto_version);
	if(!is_ok)
	{
		trace(LOG_ERR, "Unable to parse connection request");

		/* create failure answer for client */
		tlv[0] = C_CONNECT_KO;
		tlv_len++;
		// TODO : Clear client
	}
	else if(client_proto_version != CURRENT_PROTO_VERSION)
	{
		/* Current behaviour as for proto version = 1 : refuse any other version */
		trace(LOG_WARNING, "[%s] Connection refused because of wrong protocol version",
				inet_ntoa(client->tunnel.dest_address));

		/* create failure answer for client */
		tlv[0] = C_CONNECT_KO;
		tlv_len++;
		// TODO : Clear client
	}
	else
	{
		size_t len;

		trace(LOG_INFO, "[%s] Connection asked, negotating parameters "
				"(proto version %d, asked packing : %d)",
				inet_ntoa(client->tunnel.dest_address), client_proto_version,
				packing);
		client->packing = packing;

		/* create successful answer for client */
		tlv[0] = C_CONNECT_OK;
		tlv_len++;

		/* add parameters in TLV format */
		is_ok = gen_connect(client->tunnel.params, tlv + 1, &len);
		if(!is_ok)
		{
			trace(LOG_ERR, "failed to generate the connect message for client");
			goto error;
		}
		tlv_len += len;
	}

	gnutls_record_send(client->tls_session, tlv, tlv_len);

	return true;

error:
	return false;
}


int handle_client_request(struct client*client)
{
	unsigned char buf[1024];
	int length;
	unsigned char *cur;
	unsigned char *bufmax;
	bool is_ok;

	length = gnutls_record_recv(client->tls_session, buf, 1024);
	if(length == 0)
	{
		return -1;
	}
	bufmax = buf + length;
	trace(LOG_DEBUG, "[%s] Received %d bytes on TCP socket", inet_ntoa(client->tunnel.dest_address),
	      length);
	if(length < 0)
	{
		return -1;
	}

	cur = buf;
	while(cur < bufmax)
	{
		switch(*cur)
		{
			case C_CONNECT:
			{
				size_t parsed_len;

				if(++cur >= bufmax)
				{
					return -1;
				}

				is_ok = handle_connect(client, cur, cur - buf, &parsed_len);
				if(!is_ok)
				{
					return -1;
				}
				cur += parsed_len;
				break;
			}
			case C_CONNECT_DONE:
				trace(LOG_INFO, "[%s] Connection started by client",
				      inet_ntoa(client->tunnel.dest_address));
				if(start_client_tunnel(client) < 0)
				{
					return -1;
				}
				cur++;
				break;
			case C_KEEPALIVE:
				trace(LOG_DEBUG, "[%s] Received keepalive from client",
						inet_ntoa(client->tunnel.dest_address));
				gettimeofday(&(client->tunnel.last_keepalive), NULL);
				cur++;
				break;
			case C_DISCONNECT:
				trace(LOG_INFO, "[%s] Disconnection asked by client",
						inet_ntoa(client->tunnel.dest_address));
				stop_client_tunnel(client);
				cur++;
				break;
			default:
				trace(LOG_WARNING, "[%s] Unexpected command : %d",
				      inet_ntoa(client->tunnel.dest_address), *cur);
				cur++;
		}
	}
	return 0;
}


