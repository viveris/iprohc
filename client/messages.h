#include "rohc_tunnel.h"
#include "tlv.h"

#include <gnutls/gnutls.h>

/* Structure defining the options
   needed for tunnel creation
*/
struct client_opts {
    int socket ;
    gnutls_session_t  tls_session ;

	char *tun_name ;
	char *up_script_path ;

	int packing ;
} ;

/* Generic functions for handling messages */
int handle_message(struct tunnel* tunnel, char* buf, int length, struct client_opts opts) ;

/* Handlers of differents messages types */
char* handle_okconnect(struct tunnel* tunnel, char* tlv, struct client_opts opts) ;


