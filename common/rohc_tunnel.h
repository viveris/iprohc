/* rohc_tunnel.h -- Functions handling a tunnel, client or server-side
*/

#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>

#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>

/* Stucture defining a tunnel */
struct tunnel {
    struct in_addr local_address;
    struct in_addr dest_address ;
    int      tcp_socket   ;
    int      raw_socket   ;   
    pthread_t thread      ;

    int tun;  /* Real TUN device */
    int fake_tun[2] ; /* Fake TUN device for server side */
} ;

/* Called in a thread on a new tunnel */
void* new_tunnel(void* arg) ;


int tun2raw(struct rohc_comp *comp, int from, int to, struct in_addr raddr) ;
int raw2tun(struct rohc_decomp *decomp, int from, int to) ;

int read_from_tun(int fd, unsigned char *packet, unsigned int *length);
int write_to_tun(int fd, unsigned char *packet, unsigned int length);

int read_from_raw(int sock, unsigned char *buffer, unsigned int *length);
int write_to_raw(int sock, struct in_addr raddr, unsigned char *packet, unsigned int length);

int create_socket() ;

/* Structure defining param negotiated */
struct tunnel_params {
    uint32_t  local_address ;
    char      packing ;
    size_t    max_cid ;
    bool      is_unidirectional ;
    size_t    wlsb_window_width ; /* No ROHC API yet */
    int       refresh           ; /* No ROHC API yet */
    int       keepalive_timeout ;
    unsigned int rohc_compat_version ;
} ;

