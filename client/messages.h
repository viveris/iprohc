#include "rohc_tunnel.h"
#include "tlv.h"

int handle_message(struct tunnel* tunnel, int socket, char* buf, int length) ;
int client_connect(struct tunnel tunnel, int socket) ;
char* handle_okconnect(struct tunnel* tunnel, int socket, char* tlv) ;

