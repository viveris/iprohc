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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <assert.h>

#include "tlv.h"
#include "rohc_tunnel.h"
#include "tun_helpers.h"
#include "messages.h"
#include "log.h"


/* Handlers of differents messages types */
static bool handle_okconnect(struct iprohc_client_session *const client,
                             unsigned char *const data,
                             const size_t data_len,
                             size_t *const parsed_len)
	__attribute__((nonnull(1, 2, 4), warn_unused_result));


/* Generic functions for handling messages */
bool handle_message(struct iprohc_client_session *const client,
						  unsigned char *const buf,
						  const int length)
{
	size_t parsed_len;
	size_t i;

	assert(client != NULL);
	assert(buf != NULL);
	assert(length > 0);

	for(i = 0; i < length; i += parsed_len)
	{
		parsed_len = 0;

		switch(buf[i])
		{
			case C_CONNECT_OK:
			{
				size_t tlv_len;
				bool is_ok;

				parsed_len++;

				/* TODO: give remaining length */
				is_ok = handle_okconnect(client, buf + i + 1,
				                         length - i - 1, &tlv_len);
				if(!is_ok)
				{
					trace(LOG_ERR, "failed to handle CONNECT_OK message from "
					      "server, abort");
					goto error;
				}
				parsed_len += tlv_len;

				break;
			}

			case C_KEEPALIVE:
			{
				trace(LOG_DEBUG, "Received keepalive");
				gettimeofday(&(client->session.last_keepalive), NULL);
				parsed_len++;
				/* send keepalive */
				char command[1] = { C_KEEPALIVE };
				trace(LOG_DEBUG, "Keepalive !");
				gnutls_record_send(client->session.tls_session, command, 1);
				break;
			}

			case C_CONNECT_KO:
			{
				trace(LOG_ERR, "Wrong protocol version, please update client or server");
				parsed_len++;
				goto error;
			}

			default:
			{
				trace(LOG_ERR, "Unexpected 0x%02x in command", buf[i]);
				parsed_len++;
				break;
			}
		}
	}

	return true;
	
error:
	return false;
}


/* Handler of okconnect message from server */
static bool handle_okconnect(struct iprohc_client_session *const client,
                             unsigned char *const data,
                             const size_t data_len,
                             size_t *const parsed_len)
{
	struct in_addr debug_addr;
	pthread_t tunnel_thread;
	struct tunnel_params tp;
	char message[1] = { C_CONNECT_DONE };

	int pid;
	int status;
	bool is_ok;
	int ret;

	assert(client != NULL);
	assert(data != NULL);
	assert(parsed_len != NULL);

	*parsed_len = 0;

	/* Parse options received in tlv form from the server */
	is_ok = parse_connect(data, data_len, &tp, parsed_len);
	if(!is_ok)
	{
		trace(LOG_ERR, "failed to parse connect message received from the server");
		goto error;
	}

	/* Tunnel definition */
	debug_addr.s_addr = tp.local_address;
	trace(LOG_DEBUG, "Creation of tunnel, local address : %s\n", inet_ntoa(debug_addr));

	/* set params */
	client->session.tunnel.params = tp;

	/* set forced packing */
	if(client->packing != 0)
	{
		client->session.tunnel.params.packing = client->packing;
	}

	/* set the IPv4 address on the TUN interface */
	is_ok = set_ip4(client->tun_itf_id, tp.local_address, 24);
	if(!is_ok)
	{
		trace(LOG_ERR, "failed to set IP address on TUN interface");
		goto error;
	}

	/* up script */
	if(strcmp(client->up_script_path, "") != 0)
	{
		if((pid = fork()) == 0)
		{
			char*argv[4] = { "sh", "-c", client->up_script_path, NULL };

			setenv("ifconfig_local", inet_ntoa(debug_addr), 1);
			execve("/bin/sh", argv, __environ);
		}

		if(waitpid(pid, &status, 0) < 0)
		{
			trace(LOG_ERR, "Unable to start up script");
		}
		else
		{
			if(status == 0)
			{
				trace(LOG_INFO, "%s successfully executed",
				      client->up_script_path);
			}
			else
			{
				trace(LOG_WARNING, "%s exited with code %d",
				      client->up_script_path, status);
			}
		}
	}

	/* Go thread, go ! */
	trace(LOG_INFO, "run tunnel thread for new client");
	ret = pthread_create(&tunnel_thread, NULL, iprohc_tunnel_run,
	                     &(client->session));
	if(ret != 0)
	{
		trace(LOG_ERR, "failed to run tunnel thread for new client: %s (%d)",
				strerror(ret), ret);
		goto error;
	}

	gnutls_record_send(client->session.tls_session, message, 1);

	return true;

error:
	return false;
}


bool client_send_disconnect_msg(gnutls_session_t session)
{
	unsigned char command[1];
	size_t command_len;
	size_t emitted_len;
	int ret;

	assert(session != NULL);

	trace(LOG_INFO, "send disconnect message to server");

	/* build the message */
	command[0] = C_DISCONNECT;
	command_len = 1;

	/* send the message */
	emitted_len = 0;
	do
	{
		ret = gnutls_record_send(session, command + emitted_len,
										 command_len - emitted_len);
		if(ret < 0)
		{
			trace(LOG_ERR, "failed to send message to server over TLS (%d)", ret);
			goto error;
		}
		emitted_len += ret;
	}
	while(emitted_len < command_len);

	return true;

error:
	return false;
}

