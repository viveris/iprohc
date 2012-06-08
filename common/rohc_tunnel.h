/* rohc_tunnel.h -- Functions handling a tunnel, client or server-side
*/
#ifndef ROHC_IPIP_TUNNEL_H
#define ROHC_IPIP_TUNNEL_H

#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>

#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>

#include "tlv.h"

typedef void (*tunnel_close_callback_t) (void* tunnel) ;

struct statitics {
    int decomp_failed ;
    int decomp_total ;

    int comp_failed ;
    int comp_total ;

    int head_comp_size ;
    int head_uncomp_size ;

    int total_comp_size ;
    int total_uncomp_size ;

    int unpack_failed;
    int total_received;
} ;


/* Stucture defining a tunnel */
struct tunnel {
    struct in_addr dest_address ;

    int      raw_socket /* Real RAW */  ;   
    int fake_raw[2] ; /* Fake RAW device for server side */

    int tun;  /* Real TUN device */
    int fake_tun[2] ; /* Fake TUN device for server side */

    char alive ;
    struct timeval last_keepalive ;

    struct tunnel_params params ;

    struct statitics stats;

    tunnel_close_callback_t close_callback ;
} ;

/* Called in a thread on a new tunnel */
void* new_tunnel(void* arg) ;

#endif

