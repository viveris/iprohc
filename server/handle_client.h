/* handle_client.h -- Functions handling a client
*/

#include <arpa/inet.h>
#include <pthread.h>

#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>

/* Stucture defining a client */
struct client {
    struct in_addr local_address;
    struct in_addr dest_address ;
    int      raw_socket   ;   
    pthread_t thread      ;

    int tun;  /* Real TUN device */
    int fake_tun[2] ; /* Fake TUN device for server side */
} ;

/* Called in a thread on a new client */
void* new_client(void* arg) ;


int tun2raw(struct rohc_comp *comp, int from, int to, struct in_addr raddr) ;
int raw2tun(struct rohc_decomp *decomp, int from, int to) ;

