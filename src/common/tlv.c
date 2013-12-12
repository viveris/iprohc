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

/*
tlv.c -- Implements function to parse and generate tlv sequence for
communications between server and client
*/

#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "tlv.h"

/* Initialize logger */
#include <stdio.h>
#include <string.h>

#include "log.h"

#define DEBUG_STR_SIZE 1024

/* Generic function to parse tlv string */
bool parse_tlv(const unsigned char *const data,
               const size_t data_len,
					struct tlv_result *const results,
					const int max_results,
					size_t *const parsed_len)
{
	bool end_found = false;
	size_t len = 0;
	size_t i;

	assert(data != NULL);
	assert(results != NULL);
	assert(parsed_len != NULL);

	trace(LOG_DEBUG, "parse a maximum of %d parameters in TLV format on %zu "
	      "bytes", max_results, data_len);

	for((*parsed_len) = 0, i = 0;
	    (*parsed_len) < data_len && i < max_results;
	    (*parsed_len) += (3 + len), i++)
	{
		size_t j;

		/* enough data for type field? */
		if(((*parsed_len) + 1) > data_len)
		{
			trace(LOG_WARNING, "malformed TLV: 1 byte required for type while only "
			      "%zu bytes available", data_len);
			goto error;
		}

		/* parse type */
		results[i].type = data[*parsed_len];
		trace(LOG_DEBUG, "TLV: Type = 0x%02x", data[*parsed_len]);
		if(results[i].type == END)
		{
			end_found = true;
			(*parsed_len)++;
			break;
		}

		/* enough data for length field? */
		if(((*parsed_len) + 3) > data_len)
		{
			trace(LOG_WARNING, "malformed TLV (type = 0x%02x): %zu bytes "
			      "required while only %zu bytes available", results[i].type,
			      (*parsed_len) + 3, data_len);
			goto error;
		}

		/* parse length */
		len = ntohs(*((uint16_t*) (data + (*parsed_len) + 1)));
		trace(LOG_DEBUG, "TLV: Length = %zu", len);

		/* parse value */
		if(((*parsed_len) + 3 + len) > data_len)
		{
			/* not enough data for value field */
			trace(LOG_WARNING, "malformed TLV (type = 0x%02x, length = %zu): "
			      "%zu bytes required while only %zu bytes available",
			      results[i].type, len, (*parsed_len) + 3 + len, data_len);
			goto error;
		}
		results[i].value = (unsigned char *) (data + (*parsed_len) + 3);
		for(j = 0; j < len; j++)
		{
			trace(LOG_DEBUG, "TLV: Value = 0x%02x", data[(*parsed_len) + 3 + j]);
		}

		/* option is complete */
		results[i].used = true;
	}

	if(!end_found)
	{
		trace(LOG_WARNING, "TLV option 'END' not found");
		goto error;
	}

	return true;

error:
	return false;
}


/* Generic function to generate tlv string */
bool gen_tlv(unsigned char *const f_dest,
				 struct tlv_result *const tlvs,
				 const int max_numbers,
				 size_t *const length)
{
	gen_tlv_callback_t cb;
	unsigned char *dest;
	bool is_ok;
	int i;
	
	assert(f_dest != NULL);
	assert(tlvs != NULL);
	assert(length != NULL);

	dest = f_dest;
	*length = 0;

	trace(LOG_DEBUG, "Generating TLV");

	for(i = 0; i < max_numbers; i++)
	{
		size_t tlv_opt_len;

		/* type */
		*dest = tlvs[i].type;
		dest += sizeof(char);
		(*length) += sizeof(char);

		/* length, value */
		cb = get_gen_cb_for_type(tlvs[i].type);
		if(cb == NULL)
		{
			trace(LOG_ERR, "TLV parser was unable to gen type %d\n", tlvs[i].type);
			goto error;
		}

		is_ok = cb(dest, tlvs[i], &tlv_opt_len);
		if(!is_ok)
		{
			goto error;
		}
		dest += tlv_opt_len;
		*length += tlv_opt_len;

		trace(LOG_DEBUG, "generate a %zd-byte TLV option of type %d",
				1 + tlv_opt_len, tlvs[i].type);
	}

	*dest = END;
	dest++;
	(*length)++;
	trace(LOG_DEBUG, "generate a 1-byte TLV option of type END (%d)", END);

	return true;

error:
	return false;
}


/* Generation callbacks */

bool gen_tlv_uint32(unsigned char *const f_dest,
						  const struct tlv_result tlv,
						  size_t *const len)
{
	uint16_t*length;
	uint32_t*res;
	unsigned char *dest = f_dest;

	/* length */
	length  = (uint16_t*) dest;
	*length = htons(sizeof(uint32_t));
	dest  += sizeof(uint16_t);
	/* value */
	res = (uint32_t*) dest;
	*res = htonl(*((uint32_t*) tlv.value));
	dest += sizeof(uint32_t);

	*len = sizeof(uint16_t) + sizeof(uint32_t);

	return true;
}


bool gen_tlv_char(unsigned char *const f_dest,
						const struct tlv_result tlv,
						size_t *const len)
{
	uint16_t*length;
	char*res;
	unsigned char *dest = f_dest;

	/* length */
	length  = (uint16_t*) dest;
	*length = htons(sizeof(char));
	dest  += sizeof(uint16_t);
	/* value */
	res = (char*) dest;
	*res = *((char*) tlv.value);
	dest += sizeof(char);

	*len = sizeof(uint16_t) + sizeof(char);

	return true;
}


/*
 * Specific parsing
 */

/* Answer server -> client with ROHC parameters */

void mark_received(enum types *const list,
						 const int n_list,
						 const enum types type)
{
	int i;

	for(i = 0; i < n_list; i++)
	{
		if(list[i] == type)
		{
			list[i] = -1;
			return;
		}
	}
	trace(LOG_WARNING, "Unable to mark received field %d\n", type);
}


bool parse_connect(const unsigned char *const data,
                   const size_t data_len,
						 struct tunnel_params *const params,
						 size_t *const parsed_len)
{
	enum types required[N_TUNNEL_PARAMS] = {
		IP_ADDR, PACKING, MAXCID, UNID, WINDOWSIZE, REFRESH,
		KEEPALIVE, ROHC_COMPAT
	};
	struct tlv_result results[N_TUNNEL_PARAMS + 1];
	bool is_success = false;
	bool is_ok;
	int i;

	assert(data != NULL);
	assert(params != NULL);
	assert(parsed_len != NULL);

	memset(results, 0, (N_TUNNEL_PARAMS + 1) * sizeof(struct tlv_result));
	*parsed_len = 0;

	is_ok = parse_tlv(data, data_len, results, N_TUNNEL_PARAMS + 1, parsed_len);
	if(!is_ok)
	{
		trace(LOG_ERR, "parse_connect: failed to parse TLV parameters");
		goto error;
	}
	trace(LOG_DEBUG, "Parsing ok");

	for(i = 0; i < N_TUNNEL_PARAMS; i++)
	{
		if(!results[i].used)
		{
			continue;
		}

		mark_received(required, N_TUNNEL_PARAMS, results[i].type);
		switch(results[i].type)
		{
			case IP_ADDR:
				params->local_address       = ntohl(*((uint32_t*) results[i].value));
				break;
			case PACKING:
				params->packing             = *((char*) results[i].value);
				break;
			case MAXCID:
				params->max_cid             = ntohl(*((uint32_t*) results[i].value));
				break;
			case UNID:
				params->is_unidirectional   = *((char*) results[i].value);
				break;
			case WINDOWSIZE:
				params->wlsb_window_width   = ntohl(*((uint32_t*) results[i].value));
				break;
			case REFRESH:
				params->refresh             = ntohl(*((uint32_t*) results[i].value));
				break;
			case KEEPALIVE:
				params->keepalive_timeout   = ntohl(*((uint32_t*) results[i].value));
				break;
			case ROHC_COMPAT:
				params->rohc_compat_version = (*((char*) results[i].value));
				break;
			default:
				trace(LOG_ERR, "Unexpected field 0x%02x in connect", results[i].type);
				goto error;
		}
	}

	for(i = 0; i < N_TUNNEL_PARAMS; i++)
	{
		if(required[i] != -1)
		{
			trace(LOG_ERR, "Missing field in connect : %d\n", required[i]);
			goto error;
		}
	}

	is_success = true;

error:
	return is_success;
}


bool gen_connect(const struct tunnel_params params,
					  unsigned char *const dest,
					  size_t *const length)
{
	bool is_success = false;
	struct tlv_result *results;
	bool is_ok;
	int i = 0;

	assert(dest != NULL);
	assert(length != NULL);

	*length = 0;
	
	results = calloc(N_TUNNEL_PARAMS, sizeof(struct tlv_result));
	if(results == NULL)
	{
		trace(LOG_ERR, "failed to allocate memory for connect message");
		goto error;
	}

	results[i].type  = IP_ADDR;
	results[i].value = (unsigned char*) &(params.local_address);
	i++;
	results[i].type  = PACKING;
	results[i].value = (unsigned char*) &(params.packing);
	i++;
	results[i].type  = MAXCID;
	results[i].value = (unsigned char*) &(params.max_cid);
	i++;
	results[i].type  = UNID;
	results[i].value = (unsigned char*) &(params.is_unidirectional);
	i++;
	results[i].type  = WINDOWSIZE;
	results[i].value = (unsigned char*) &(params.wlsb_window_width);
	i++;
	results[i].type  = REFRESH;
	results[i].value = (unsigned char*) &(params.refresh);
	i++;
	results[i].type  = KEEPALIVE;
	results[i].value = (unsigned char*) &(params.keepalive_timeout);
	i++;
	results[i].type  = ROHC_COMPAT;
	results[i].value = (unsigned char*) &(params.rohc_compat_version);
	i++;

	is_ok = gen_tlv(dest, results, N_TUNNEL_PARAMS, length);
	if(!is_ok)
	{
		trace(LOG_ERR, "failed to create options in TLV format");
		goto free_results;
	}

	is_success = true;

free_results:
	free(results);
error:
	return is_success;
}


/* Connection request (client -> server) */
bool parse_connrequest(const unsigned char *const data,
                       const size_t data_len,
							  size_t *const parsed_len,
							  int *const packing,
							  int *const proto_version)
{
	struct tlv_result results[N_CONNREQ_FIELD + 1];
	bool is_success = false;
	bool is_ok;
	size_t err_nr;
	int i;

	assert(data != NULL);
	assert(parsed_len != NULL);
	assert(packing != NULL);
	assert(proto_version != NULL);

	memset(results, 0, (N_CONNREQ_FIELD + 1) * sizeof(struct tlv_result));
	*parsed_len = 0;

	is_ok = parse_tlv(data, data_len, results, N_CONNREQ_FIELD + 1, parsed_len);
	if(!is_ok)
	{
		trace(LOG_ERR, "parse_connrequest: failed to parse TLV parameters");
		goto error;
	}

	err_nr = 0;
	for(i = 0; i < N_CONNREQ_FIELD && results[i].used; i++)
	{
		if(results[i].type == CPACKING)
		{
			trace(LOG_DEBUG, "connection request: parameter PACKING (%u) found",
			      results[i].type);
			*packing = *((char*) results[i].value);
		}
		else if(results[i].type == CPROTO_VERSION)
		{
			trace(LOG_DEBUG, "connection request: parameter PROTO_VERSION (%u) "
			      "found", results[i].type);
			*proto_version = *((char*) results[i].value);
		}
		else
		{
			trace(LOG_WARNING, "connection request: unexpected parameter %u",
			      results[i].type);
			err_nr++;
		}
	}

	is_success = (err_nr == 0);

error:
	return is_success;
}


bool gen_connrequest(const int packing,
							unsigned char *const dest,
							size_t *const length)
{
	const int version = CURRENT_PROTO_VERSION;
	struct tlv_result *results;
	bool is_success = false;
	bool is_ok;

	assert(dest != NULL);
	assert(length != NULL);

	*length = 0;

	trace(LOG_DEBUG, "Generating TLV connrequest");

	results = calloc(N_CONNREQ_FIELD, sizeof(struct tlv_result));
	if(results == NULL)
	{
		trace(LOG_ERR, "failed to allocate memory for parsed parameters");
		goto error;
	}

	results[0].type  = CPACKING;
	results[0].value = (unsigned char*) &packing;

	results[1].type  = CPROTO_VERSION;
	results[1].value = (unsigned char*) &version;

	is_ok = gen_tlv(dest, results, N_CONNREQ_FIELD, length);
	if(!is_ok)
	{
		trace(LOG_ERR, "failed to create parameters in TLV format");
		goto free_results;
	}

	is_success = true;

free_results:
	free(results);
error:
	return is_success;
}


