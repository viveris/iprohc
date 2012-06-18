#include <time.h>

#include "rohc_tunnel.h"
#include "tlv.h"

#include "server.h"

struct client {    
    int      tcp_socket   ;
    gnutls_session_t tls_session;
    struct in_addr local_address;

    pthread_t thread_tunnel;
    struct tunnel tunnel ;

    struct timeval last_keepalive ;
} ;

int  new_client(int socket, int tun, struct client** clients, int max_clients, struct server_opts server_opts) ;
void close_tunnel(void* tunnel) ;
int  start_client_tunnel(struct client* client) ;

