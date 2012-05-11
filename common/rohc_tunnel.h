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

    tunnel_close_callback_t close_callback ;
} ;

/* Called in a thread on a new tunnel */
void* new_tunnel(void* arg) ;

int create_raw() ;

int tun2raw(struct rohc_comp *comp, int from, int to, struct in_addr raddr) ;
int raw2tun(struct rohc_decomp *decomp, int from, int to) ;

int read_from_tun(int fd, unsigned char *packet, unsigned int *length);
int write_to_tun(int fd, unsigned char *packet, unsigned int length);

int read_from_raw(int sock, unsigned char *buffer, unsigned int *length);
int write_to_raw(int sock, struct in_addr raddr, unsigned char *packet, unsigned int length);

int create_socket() ;


#endif

