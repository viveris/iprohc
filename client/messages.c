#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "tlv.h"
#include "rohc_tunnel.h"
#include "tun_helpers.h"

#define TUNTAP_BUFSIZE 1518

#include <syslog.h>
#define MAX_LOG LOG_INFO
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)

int client_connect(struct tunnel tunnel)
{
	char command[1] = { C_CONNECT } ;
	trace(LOG_DEBUG, "Emit connect message") ;
	/* Emit a simple connect message */
	send(tunnel.tcp_socket, command, 1 ,0) ;
	return 1 ;
}

char* handle_okconnect(struct tunnel* tunnel, char* tlv) {
	int tun, raw ;
	int tun_itf_id ;
	struct in_addr local;
	struct in_addr debug_addr;
	pthread_t tunnel_thread ;
	struct tunnel_params tp ;
	char message[1] = { C_CONNECT_DONE } ;
	char* newbuf ;

	newbuf = parse_connect(tlv, &tp) ;
	if (newbuf == NULL) {
		return NULL ;
	}

	/* Tunnel definition */
	debug_addr.s_addr = tp.local_address ;
	trace(LOG_DEBUG, "Creation of tunnel, local address : %s\n", inet_ntoa(debug_addr)) ;

	/* local_addr */
	local.s_addr = tp.local_address ;
	tunnel->local_address = local ;

	/* set tun */
	tun = create_tun("rohc_ipc", &tun_itf_id) ;
	set_ip4(tun_itf_id, tp.local_address, 24) ; /* 192.168.99.23/24 */
	tunnel->tun = tun ; /* real tun device */
	tunnel->fake_tun[0] = -1 ;
	tunnel->fake_tun[1] = -1 ;

    /* set RAW  */
    raw = create_raw() ;
    if (raw < -1) {
        trace(LOG_ERR, "Unable to create TUN device") ;
        return NULL ;
    }
	tunnel->raw_socket  = raw ;
	tunnel->fake_raw[0] = -1 ;
	tunnel->fake_raw[1] = -1 ;

	/* set params */
	tunnel->params = tp ;
 
    /* Go thread, go ! */
	pthread_create(&tunnel_thread, NULL, new_tunnel, (void*)tunnel) ;

	send(tunnel->tcp_socket, message, 1, 0) ;

	return newbuf ;
}
