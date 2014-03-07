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

#ifndef ROHC_IPIP_TLV_H
#define ROHC_IPIP_TLV_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


#define IPROHC_PROTO_VERSION_FIRST         1
#define IPROHC_PROTO_VERSION_ROHC_COMPAT   2

/* Defines the current protocol version, must be modified each time
   a field is added or removed */
#define CURRENT_PROTO_VERSION  IPROHC_PROTO_VERSION_ROHC_COMPAT

/* Global structures */
enum commands
{
	C_CONNECT       = 0,
	C_CONNECT_OK    = 1,
	C_CONNECT_KO    = 2,
	C_CONNECT_DONE  = 3,
	C_DISCONNECT    = 4,
	C_KEEPALIVE     = 5,
};

enum types
{
	END            =  0,
	/* connect types */
	IP_ADDR        =  1,
	PACKING        =  2,
	MAXCID         =  3,
	UNID           =  4,
	WINDOWSIZE     =  5,
	REFRESH        =  6,
	KEEPALIVE      =  7,
	ROHC_COMPAT    =  8,
	/* connrequest types */
	CPACKING       =  9,
	CPROTO_VERSION = 10,
};

#define N_CONNECT_FIELD 8
#define N_CONNREQ_FIELD_FIRST        2
#define N_CONNREQ_FIELD_ROHC_COMPAT  3
#define N_CONNREQ_FIELD              N_CONNREQ_FIELD_ROHC_COMPAT

struct tlv_result
{
	bool used;
	char type;
	uint16_t length;
	unsigned char*value;
};

/* Global parsing and generation functions */
bool parse_tlv(const unsigned char *const data,
               const size_t data_len,
					struct tlv_result *const results,
					const int max_results,
					size_t *const parsed_len)
	__attribute__((nonnull(1, 3, 5), warn_unused_result));

bool gen_tlv(unsigned char *const f_dest,
				 struct tlv_result *const tlvs,
				 const int max_numbers,
				 size_t *const length)
	__attribute__((nonnull(1, 2, 4), warn_unused_result));

/* Callbacks for generation */
typedef bool (*gen_tlv_callback_t)(unsigned char *const dest,
											  const struct tlv_result tlv,
											  size_t *const len);

bool gen_tlv_uint32(unsigned char *const dest,
						  const struct tlv_result tlv,
						  size_t *const len);
bool gen_tlv_char(unsigned char *const dest,
						const struct tlv_result tlv,
						size_t *const len);

/* Association between callbacks and type */
static inline gen_tlv_callback_t get_gen_cb_for_type(enum types type)
{
	switch(type)
	{
		case IP_ADDR:
			return gen_tlv_uint32;
		case PACKING:
			return gen_tlv_char;
		case MAXCID:
			return gen_tlv_uint32;
		case UNID:
			return gen_tlv_char;
		case WINDOWSIZE:
			return gen_tlv_uint32;
		case REFRESH:
			return gen_tlv_uint32;
		case KEEPALIVE:
			return gen_tlv_uint32;
		case ROHC_COMPAT:
			return gen_tlv_char;
		case CPACKING:
			return gen_tlv_char;
		case CPROTO_VERSION:
			return gen_tlv_char;
		default:
			return NULL;
	}
}


/*
Specific parsing
*/

/* Structure defining param negotiated */
/* Number of fields */
#define N_TUNNEL_PARAMS 8

struct tunnel_params
{
	uint32_t local_address;
	char packing;
	size_t max_cid;
	char is_unidirectional;
	size_t wlsb_window_width;      /* No ROHC API yet */
	size_t refresh;                /* No ROHC API yet */
	size_t keepalive_timeout;
	char rohc_compat_version;
};

#define IPROHC_ROHC_COMPAT_1_6_x   1
#define IPROHC_ROHC_COMPAT_1_7_x   2
#define IPROHC_ROHC_COMPAT_LAST    IPROHC_ROHC_COMPAT_1_7_x

bool parse_connect(const unsigned char *const data,
                   const size_t data_len,
						 struct tunnel_params *const params,
						 size_t *const parsed_len)
	__attribute__((nonnull(1, 3, 4), warn_unused_result));

bool gen_connect(const struct tunnel_params params,
					  unsigned char *const dest,
					  size_t *const length)
	__attribute__((nonnull(2, 3), warn_unused_result));

bool parse_connrequest(const unsigned char *const data,
                       const size_t data_len,
							  size_t *const parsed_len,
							  int *const packing,
							  int *const proto_version,
							  int *const rohc_compat_version)
	__attribute__((nonnull(1, 3, 4, 5, 6), warn_unused_result));

bool gen_connrequest(const int packing,
							unsigned char *const dest,
							size_t *const length)
	__attribute__((nonnull(2, 3), warn_unused_result));

#endif

