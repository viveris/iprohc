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
#include <stdint.h>

#ifndef ROHC_IPIP_TLV_H
#define ROHC_IPIP_TLV_H

/* Defines the current protocol version, must be modified each time 
   a field is added or removed */
#define CURRENT_PROTO_VERSION 1

/* Global structures */
enum commands {
    C_CONNECT,
    C_CONNECT_OK,
    C_CONNECT_KO,
    C_CONNECT_DONE,
    C_DISCONNECT,
    C_KEEPALIVE
} ;

enum types {
    END,
    /* connect types */
    IP_ADDR,
    PACKING,
    MAXCID,
    UNID,
    WINDOWSIZE,
    REFRESH,
    KEEPALIVE,
    ROHC_COMPAT,
    /* connrequest types */
    CPACKING,
    CPROTO_VERSION
} ;

#define N_CONNECT_FIELD 8
#define N_CONNREQ_FIELD 2

enum parse_step {
    TYPE,
    LENGTH,
    VALUE
} ;

struct tlv_result {
    char        type ;
    uint16_t     length ;
    unsigned char* value ;
} ;

/* Global parsing and generation functions */
char* parse_tlv(char* tlv, struct tlv_result** results, int max_results) ;
size_t gen_tlv(char* dest, struct tlv_result* tlvs, int max_numbers) ;

/* Callbacks for generation */

typedef char* (*gen_tlv_callback_t) (char* dest, struct tlv_result tlv, size_t* len) ;

char* gen_tlv_uint32(char* dest, struct tlv_result tlv, size_t* len) ;
char* gen_tlv_char(char* dest, struct tlv_result tlv, size_t* len) ;

/* Association between callbacks and type */
static inline gen_tlv_callback_t get_gen_cb_for_type(enum types type) {
    switch (type) {
        case IP_ADDR:
            return gen_tlv_uint32 ;
        case PACKING :
            return gen_tlv_char   ;
        case MAXCID :
            return gen_tlv_uint32 ;
        case UNID :
            return gen_tlv_char   ;
        case WINDOWSIZE :
            return gen_tlv_uint32 ;
        case REFRESH :
            return gen_tlv_uint32 ;
        case KEEPALIVE :
            return gen_tlv_uint32 ;
        case ROHC_COMPAT :
            return gen_tlv_char   ;
        case CPACKING :
            return gen_tlv_char ;
        case CPROTO_VERSION :
            return gen_tlv_char ;
        default:
            return NULL ;
    }
}

/*
Specific parsing
*/

/* Structure defining param negotiated */
/* Number of fields */
#define N_TUNNEL_PARAMS 8

struct tunnel_params {
    uint32_t  local_address ;
    char      packing ;
    size_t    max_cid ;
    char      is_unidirectional ;
    size_t    wlsb_window_width ; /* No ROHC API yet */
    size_t    refresh           ; /* No ROHC API yet */
    size_t    keepalive_timeout ;
    char      rohc_compat_version ;
} ;

char*  parse_connect(char* buffer, struct tunnel_params* params) ;
size_t gen_connect(char* dest, struct tunnel_params params) ;

char* parse_connrequest(char* buffer, int* packing, int* proto_version) ;
size_t gen_connrequest(char* dest, int packing) ;
#endif
