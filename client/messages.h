#include "rohc_tunnel.h"
#include "tlv.h"

struct client_opts {
	char *tun_name ;
	char *up_script_path ;
} ;

int handle_message(struct tunnel* tunnel, int socket, char* buf, int length, struct client_opts opts) ;
int client_connect(struct tunnel tunnel, int socket) ;
char* handle_okconnect(struct tunnel* tunnel, int socket, char* tlv, struct client_opts opts) ;

