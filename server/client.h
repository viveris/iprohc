#include "rohc_tunnel.h"

int  new_client(int socket, int tun, int raw, struct tunnel** clients, struct tunnel_params params) ;
void close_client(void* client) ;
int  start_client_tunnel(struct tunnel* client) ;

