#include "rohc_tunnel.h"
#include "tlv.h"

/* Structure defining the options
   needed for tunnel creation
*/
struct client_opts {
	char *tun_name ;
	char *up_script_path ;
} ;

/* Send connection request */
int client_connect(struct tunnel tunnel, int socket) ;

/* Generic functions for handling messages */
int handle_message(struct tunnel* tunnel, int socket, char* buf, int length, struct client_opts opts) ;

/* Handlers of differents messages types */
char* handle_okconnect(struct tunnel* tunnel, int socket, char* tlv, struct client_opts opts) ;


