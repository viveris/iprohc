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

/* config.c -- Parse config file

Config file is in (very) basic yaml format :
general:
   port: xxx
   pidfile: xxx
   p12: xxx

tunnel:
   packing: xxx
   maxcid: xxx

Only general and rohc are allowed, all the others are ignored, with a warning.
The parser is deliberately simple for this use case so it :
 - limit the indentation to maximum 2
 - forbids sequence

*/

#include "log.h"
#include "server.h"

#include <errno.h>
#include <yaml.h>
#include <arpa/inet.h>



#define MAX_LEVEL 3

enum parse_state
{
	WAIT_NODE1,
	WAIT_NODE2
};


static bool iprohc_server_parse_config(const char *const conf_file,
                                       struct server_opts *const server_opts)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool iprohc_server_handle_config_line(const char *const section,
                                             const char *const key,
                                             const char *const value,
                                             struct server_opts *const server_opts)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 4)));

static size_t iprohc_get_ipv4_range_width(const uint32_t addr,
                                          const size_t netmasklen)
	__attribute__((warn_unused_result));

static void dump_opts(const struct server_opts *const opts)
	__attribute__((nonnull(1)));



/**
 * @brief Load configuration from file for the IP/ROHC server
 *
 * @param conf_file            The path to the configuration file
 * @param[in,out] server_opts  The configuration loaded from file
 * @return                     true is configuration is successfully loaded,
 *                             false if a problem occurred
 */
bool iprohc_server_load_config(const char *const conf_file,
                               struct server_opts *const server_opts)
{
	size_t range_len;

	if(!iprohc_server_parse_config(conf_file, server_opts))
	{
		trace(LOG_ERR, "failed to parse configuration file '%s'", conf_file);
		goto error;
	}

	range_len = iprohc_get_ipv4_range_width(ntohl(server_opts->local_address),
	                                        server_opts->netmask);
	if(server_opts->clients_max_nr > range_len)
	{
		trace(LOG_ERR, "invalid configuration: not enough IP addresses for %zu "
		      "clients: only %zu IP addresses available in %u.%u.%u.%u/%zu",
		      server_opts->clients_max_nr, range_len,
		      (ntohl(server_opts->local_address) >> 24) & 0xff,
		      (ntohl(server_opts->local_address) >> 16) & 0xff,
		      (ntohl(server_opts->local_address) >>  8) & 0xff,
		      (ntohl(server_opts->local_address) >>  0) & 0xff,
		      server_opts->netmask);
		goto error;
	}
	trace(LOG_INFO, "%zu IP addresses available for %zu clients in IP range "
	      "%u.%u.%u.%u/%zu", range_len, server_opts->clients_max_nr,
	      (ntohl(server_opts->local_address) >> 24) & 0xff,
	      (ntohl(server_opts->local_address) >> 16) & 0xff,
	      (ntohl(server_opts->local_address) >>  8) & 0xff,
	      (ntohl(server_opts->local_address) >>  0) & 0xff,
	      server_opts->netmask);

	if(strcmp(server_opts->basedev, "") == 0)
	{
		trace(LOG_ERR, "wrong usage: underlying interface name is mandatory, "
		      "use the --basedev or -b option to specify it");
		goto error;
	}

	if(strcmp(server_opts->pkcs12_f, "") == 0)
	{
		trace(LOG_ERR, "PKCS12 file required");
		goto error;
	}

	dump_opts(server_opts);

	return true;

error:
	return false;
}


/**
 * @brief Parse the given configuration file
 *
 * @param conf_file            The path to the configuration file
 * @param[in,out] server_opts  The configuration loaded from file
 * @return                     true is configuration is successfully loaded,
 *                             false if a problem occurred
 */
static bool iprohc_server_parse_config(const char *const conf_file,
                                       struct server_opts *const server_opts)
{
	FILE *input;
	yaml_parser_t parser;
	yaml_event_t event;

	int level = 0;
	enum parse_state states[MAX_LEVEL];

	char section[1024];
	char key[1024];
	char value[1024];

	int done = 0;

	input = fopen(conf_file, "rb");
	if(input == NULL)
	{
		trace(LOG_ERR, "failed to open configuration file '%s': %s (%d)",
		      conf_file, strerror(errno), errno);
		goto error;
	}

	yaml_parser_initialize(&parser);
	yaml_parser_set_input_file(&parser, input);

	while(!done)
	{
		if(!yaml_parser_parse(&parser, &event))
		{
			goto close_file;
		}

		switch(event.type)
		{

			case YAML_MAPPING_START_EVENT:
				level++;
				if(level >= MAX_LEVEL)
				{
					trace(LOG_ERR, "Too much level of ident");
					goto close_file;
				}
				states[level] = WAIT_NODE1;
				break;

			case YAML_MAPPING_END_EVENT:
				level--;
				states[level] = WAIT_NODE1;
				break;

			case YAML_SCALAR_EVENT:
				switch(states[level])
				{
					case WAIT_NODE1:
						if(level == 1)
						{
							strncpy(section, (char*) event.data.scalar.value, event.data.scalar.length + 1);
						}
						else if(level == 2)
						{
							strncpy(key, (char*) event.data.scalar.value, event.data.scalar.length + 1);
						}
						states[level] = WAIT_NODE2;
						break;
					case WAIT_NODE2:
						if(level == 2)
						{
							strncpy(value, (char*) event.data.scalar.value, event.data.scalar.length + 1);
							if(!iprohc_server_handle_config_line(section, key, value,
							                                     server_opts))
							{
								goto error;
							}
							states[level] = WAIT_NODE1;
						}
						break;
				}
				break;

			case YAML_SEQUENCE_START_EVENT:
			case YAML_SEQUENCE_END_EVENT:
				trace(LOG_WARNING, "Unexpected sequence in iprohc config file");
				break;
			case YAML_ALIAS_EVENT:
				trace(LOG_WARNING, "Unexpected alias in iprohc config file");
				break;
			default:
				break;
		}

		done = (event.type == YAML_STREAM_END_EVENT);
		yaml_event_delete(&event);
	}

	yaml_parser_delete(&parser);
	fclose(input);

	return true;

close_file:
	yaml_parser_delete(&parser);
	fclose(input);
error:
	return false;
}


/**
 * @brief Parse one line of configuration
 *
 * @param section              The name of the configuration section
 * @param key                  The name of the configuration item
 * @param value                The value of the configuration item
 * @param[in,out] server_opts  The configuration loaded from file
 * @return                     true is configuration is successfully loaded,
 *                             false if a problem occurred
 */
static bool iprohc_server_handle_config_line(const char *const section,
                                             const char *const key,
                                             const char *const value,
                                             struct server_opts *const server_opts)
{
	trace(LOG_DEBUG, "Conf [%s] %s => %s", section, key, value);

	if(strcmp(section, "general") == 0)
	{
		if(strcmp(key, "max_clients") == 0)
		{
			const int num = atoi(value);
			if(num <= 0)
			{
				trace(LOG_ERR, "invalid configuration: value for attribute "
				      "'max_clients' shall be strictly greater than zero, but %d "
				      "found", num);
				goto error;
			}
			server_opts->clients_max_nr = num;
		}
		else if(strcmp(key, "port") == 0)
		{
			server_opts->port = atoi(value);
		}
		else if(strcmp(key, "pidfile") == 0)
		{
			strncpy(server_opts->pidfile_path, value, 1024);
		}
		else if(strcmp(key, "p12file") == 0)
		{
			strncpy(server_opts->pkcs12_f, value, 1024);
		}
		else
		{
			trace(LOG_ERR, "invalid configuration: unexpected attribute '%s' "
			      "found in section '%s'", key, section);
			goto error;
		}
	}
	else if(strcmp(section, "tunnel") == 0)
	{
		if(strcmp(key, "ipaddr") == 0)
		{
			/* handle a.b.c.d or a.b.c.d/e (if /e is missing, use /24) */
			char *slash = strchr(value, '/');
			if(slash == NULL)
			{
				/* format is a.b.c.d */
				server_opts->local_address = inet_addr(value);
				server_opts->netmask = 24;
			}
			else
			{
				/* format is a.b.c.d/e */
				int num;
				slash[0] = '\0';
				server_opts->local_address = inet_addr(value);
				num = atoi(slash + 1);
				if(num <= 0 || num >= 32)
				{
					trace(LOG_ERR, "invalid configuration: netmask shall be in range "
					      "]0,32[ but %d found", num);
					goto error;
				}
				server_opts->netmask = num;
			}
		}
		else if(strcmp(key, "packing") == 0)
		{
			server_opts->params.packing = atoi(value);
		}
		else if(strcmp(key, "maxcid") == 0)
		{
			server_opts->params.max_cid = atoi(value);
		}
		else if(strcmp(key, "unidirectional") == 0)
		{
			server_opts->params.is_unidirectional = atoi(value);
		}
		else if(strcmp(key, "keepalive") == 0)
		{
			server_opts->params.keepalive_timeout = atoi(value);
		}
		else
		{
			trace(LOG_ERR, "invalid configuration: unexpected attribute '%s' "
			      "found in section '%s'", key, section);
			goto error;
		}
	}
	else
	{
		trace(LOG_ERR, "invalid configuration: unexpected section '%s'", section);
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Compute the width of the given IP range
 *
 * @param addr        The local IP address of the server (in host byte order)
 * @param netmasklen  The length (in bits) of the network mask
 * @return            The number of IP addresses available in the IP range
 */
static size_t iprohc_get_ipv4_range_width(const uint32_t addr,
                                          const size_t netmasklen)
{
	size_t range_len = (1 << (32 - netmasklen));
	const uint32_t netmask = (0xffffffff << (32 - netmasklen));

	/* if a.b.c.0 is in IP range, it cannot be used */
	if(((addr & netmask) & 0xff) == 0)
	{
		range_len--;
	}

	return range_len;
}


/**
 * @brief Print the configuration of the IP/ROHC server in logs
 *
 * @param opts  The server configuration
 */
static void dump_opts(const struct server_opts *const opts)
{
	struct in_addr addr;
	addr.s_addr = opts->local_address;

	trace(LOG_INFO, "Max clients : %zu", opts->clients_max_nr);
	trace(LOG_INFO, "Port        : %d", opts->port);
	trace(LOG_INFO, "P12 file    : %s", opts->pkcs12_f);
	trace(LOG_INFO, "Pidfile     : %s", opts->pidfile_path);
	trace(LOG_INFO, "Tunnel params :");
	trace(LOG_INFO, " . Local IP  : %s/%zu", inet_ntoa(addr), opts->netmask);
	trace(LOG_INFO, " . Packing   : %d", opts->params.packing);
	trace(LOG_INFO, " . Max cid   : %zu", opts->params.max_cid);
	trace(LOG_INFO, " . Unid      : %d", opts->params.is_unidirectional);
	trace(LOG_INFO, " . Keepalive : %zu", opts->params.keepalive_timeout);
}

