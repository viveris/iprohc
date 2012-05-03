#include <stdint.h>

#ifndef ROHC_IPIP_TLV_H
#define ROHC_IPIP_TLV_H

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
} ;

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
gen_tlv_callback_t get_gen_cb_for_type(enum types type) ;

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

#endif
