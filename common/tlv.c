/* 
tlv.c -- Implements function to parse and generate tlv sequence for
communications between server and client
*/

#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>
#include "tlv.h"

/* Initialize logger */
#include <stdio.h>
#include <string.h>

#include "log.h"

#define DEBUG_STR_SIZE 1024

/* Generic function to parse tlv string */
char* parse_tlv(char* tlv, struct tlv_result** results, int max_results)
{
	enum parse_step step = TYPE ;
	struct tlv_result* result ;
	int i=0 ;
	int j;
	uint16_t len ;
	char* c = tlv ;
	int alive = 1 ;
	char debug[DEBUG_STR_SIZE] ;
	char temp_debug[DEBUG_STR_SIZE] ;
	
	while (alive && i < max_results) {
		switch (step) {
			case TYPE:
				result = malloc(sizeof(struct tlv_result)) ;
				result->type = *c ;
				snprintf(debug, DEBUG_STR_SIZE, "Type : %x, ", *c) ;
				c += sizeof(result->type) ;
				break ;
			case LENGTH:
				len = ntohs(*((uint16_t*) c)) ;
				c  += sizeof(len) ;
				snprintf(temp_debug, DEBUG_STR_SIZE, "length : %d,", len) ;
				strncat(debug, temp_debug, DEBUG_STR_SIZE) ;
				break;
			case VALUE :
				result->value = (unsigned char*) c ;	
				snprintf(temp_debug, DEBUG_STR_SIZE, "value :  ") ;
				strncat(debug, temp_debug, DEBUG_STR_SIZE) ;
				for (j=0; j<len; j++) {
					snprintf(temp_debug, DEBUG_STR_SIZE, "%x:", *(c+j)) ;
					strncat(debug, temp_debug, DEBUG_STR_SIZE) ;
				}
				trace(LOG_DEBUG, debug) ;
				c += len ;
	
				results[i] = result ;
				i++ ;
				break ;
		}
		
		/* Switch to next step */
		step = (step + 1) % 3 ;
		if (step == TYPE && *c == END) {
			alive = 0 ;
			c++ ;
		}
	}

	if (i == max_results && alive) {
		return NULL ;
	}

	return c ;
}

/* Generic function to generate tlv string */
size_t gen_tlv(char* f_dest, struct tlv_result* tlvs, int max_numbers)
{
	int i ;
	gen_tlv_callback_t cb ;
	size_t len = 0 ;
	char* dest = f_dest ;
	trace(LOG_DEBUG, "Generating TLV") ;

	for (i=0; i < max_numbers; i++) {
		/* type */
		*dest = tlvs[i].type ;		
		dest += sizeof(char) ;
		len  += sizeof(char) ;
		/* length, value */
		cb = get_gen_cb_for_type(tlvs[i].type) ;	
		if (cb == NULL) {
			trace(LOG_ERR, "TLV parser was unable to gen type %d\n" , tlvs[i].type) ;
			return -1 ;
		}
		dest = cb(dest, tlvs[i], &len) ;
	}

	*dest = END ;
	len+= sizeof(char) ;

	return len ;
}


/* Generation callbacks */

char* gen_tlv_uint32(char* f_dest, struct tlv_result tlv, size_t* len)
{
	uint16_t* length ;
	uint32_t* res ;
	char* dest = f_dest ;
	
	/* length */
	length  = (uint16_t*) dest ;
	*length = htons(sizeof(uint32_t)) ;
	dest  += sizeof(uint16_t) ;
	/* value */
	res = (uint32_t*) dest ;
	*res = htonl(*((uint32_t*) tlv.value)) ;	
	dest += sizeof(uint32_t) ;

	*len += sizeof(uint16_t) + sizeof(uint32_t) ;

	return dest ;
}

char* gen_tlv_char(char* f_dest, struct tlv_result tlv, size_t* len)
{
	uint16_t* length ;
	char* res ;
	char* dest = f_dest ;
	
	/* length */
	length  = (uint16_t*) dest ;
	*length = htons(sizeof(char)) ;
	dest  += sizeof(uint16_t) ;
	/* value */
	res = (char*) dest ;
	*res = *((char*) tlv.value) ;	
	dest += sizeof(char) ;

	*len += sizeof(uint16_t) + sizeof(char) ;

	return dest ;
}

/* 
 * Specific parsing 
 */

/* Answer server -> client with ROHC parameters */

void mark_received(enum types* list, int n_list, enum types type)
{
	int i;
	
	for (i=0; i < n_list; i++) {
		if (list[i] == type) {
			list[i] = -1 ;
			return ;
		}
	}
	trace(LOG_WARNING, "Unable to mark received field %d\n", type) ;
	return ;
}


char* parse_connect(char* buffer, struct tunnel_params* params)
{
	int i ;
	char* newbuf ;
	/* At most n parameters can be retrieved */
	struct tlv_result** results = calloc(N_TUNNEL_PARAMS, sizeof(struct tlv_result*)) ;
	enum types required[N_TUNNEL_PARAMS] = { IP_ADDR, PACKING, MAXCID, UNID, WINDOWSIZE, REFRESH,
	                        KEEPALIVE, ROHC_COMPAT} ;
	
	newbuf = parse_tlv(buffer, results, N_TUNNEL_PARAMS) ;
	if (newbuf == NULL) {
		trace(LOG_ERR, "Parsing ERR") ;
		return NULL ;
	}
	trace(LOG_DEBUG, "Parsing ok") ;

	for (i=0; i<N_TUNNEL_PARAMS; i++) {
		if (results[i] != NULL) {
			mark_received(required, N_TUNNEL_PARAMS, results[i]->type) ;
			switch(results[i]->type) {
				case IP_ADDR:
					params->local_address       = ntohl(*((uint32_t*) results[i]->value)) ;
					break ;
				case PACKING :
					params->packing             = *((char*) results[i]->value) ;
					break ;
				case MAXCID :
					params->max_cid             = ntohl(*((uint32_t*) results[i]->value)) ;
					break ;
				case UNID :
					params->is_unidirectional   = *((char*) results[i]->value) ;
					break ;
				case WINDOWSIZE :
					params->wlsb_window_width   = ntohl(*((uint32_t*) results[i]->value)) ;
					break ;
				case REFRESH :
					params->refresh             = ntohl(*((uint32_t*) results[i]->value)) ;
					break ;
				case KEEPALIVE :
					params->keepalive_timeout   = ntohl(*((uint32_t*) results[i]->value)) ;
					break ;
				case ROHC_COMPAT :
					params->rohc_compat_version = (*((char*) results[i]->value)) ;
					break ;
				default :
					trace(LOG_ERR, "Unexpected field in connect : %x\n", results[i]->type) ;
					free(results) ;
					return NULL ;
			}
			free(results[i]) ;
		}
	}

	for (i=0; i<N_TUNNEL_PARAMS; i++) {
		if (required[i] != -1) {
			trace(LOG_ERR, "Missing field in connect : %d\n", required[i]) ;
			free(results) ;
			return NULL ;
		}
	}
	free(results) ;

	return newbuf ;
}

size_t gen_connect(char* dest, struct tunnel_params params)
{
	int i=0 ;
	int ret ;
	struct tlv_result* results = calloc(N_TUNNEL_PARAMS, sizeof(struct tlv_result)) ;

	results[i].type  = IP_ADDR ;
	results[i].value = (unsigned char*) &(params.local_address) ;
	i++ ;
	results[i].type  = PACKING ;
	results[i].value = (unsigned char*) &(params.packing) ;
	i++ ;
	results[i].type  = MAXCID ;
	results[i].value = (unsigned char*) &(params.max_cid) ;
	i++ ;
	results[i].type  = UNID ;
	results[i].value = (unsigned char*) &(params.is_unidirectional) ;
	i++ ;
	results[i].type  = WINDOWSIZE ;
	results[i].value = (unsigned char*) &(params.wlsb_window_width) ;
	i++ ;
	results[i].type  = REFRESH ;
	results[i].value = (unsigned char*) &(params.refresh) ;
	i++ ;
	results[i].type  = KEEPALIVE ;
	results[i].value = (unsigned char*) &(params.keepalive_timeout) ;
	i++ ;
	results[i].type  = ROHC_COMPAT ;
	results[i].value = (unsigned char*) &(params.rohc_compat_version) ;
	i++ ;

	ret = gen_tlv(dest, results, N_TUNNEL_PARAMS) ;
	free(results) ;
	return ret ;
}

/* Connection request (client -> server) */

char* parse_connrequest(char* buffer, int* packing)
{
	char* newbuf ;
	struct tlv_result** results = calloc(1, sizeof(struct tlv_result*)) ;
	
	newbuf = parse_tlv(buffer, results, 1) ;
	if (newbuf == NULL) {
		trace(LOG_ERR, "Parsing ERR") ;
		return NULL ;
	}
	trace(LOG_DEBUG, "Parsing ok") ;

	if (results[0] != NULL && results[0]->type == CPACKING) {
			*packing = *((char*) results[0]->value) ;
	} else {
		trace(LOG_ERR, "Missing field in connect request : packing\n") ;
		newbuf = NULL ;
	}
	free(results) ;

	return newbuf ;
}

size_t gen_connrequest(char* dest, int packing)
{
	trace(LOG_DEBUG, "Generating TLV connrequest") ;
	struct tlv_result* results = calloc(1, sizeof(struct tlv_result)) ;
	int ret ;

	results[0].type  = CPACKING ;
	results[0].value = (unsigned char*) &packing ;

    ret = gen_tlv(dest, results, 1) ;
    free(results) ;
    return ret ;
}
