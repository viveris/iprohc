#include <time.h>

#include "rohc_tunnel.h"
#include "keepalive.h"
#include "tlv.h"

struct client {    
    int      tcp_socket   ;
    struct in_addr local_address;

    pthread_t thread_tunnel;
    struct tunnel tunnel ;

    struct timeval last_keepalive ;
} ;

int  new_client(int socket, int tun, int raw, struct client** clients, int max_clients, struct tunnel_params params) ;
void close_tunnel(void* tunnel) ;
int  start_client_tunnel(struct client* client) ;

