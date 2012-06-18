#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include "tlv.h"
#include "rohc_tunnel.h"
#include "tun_helpers.h"

#include "messages.h"

#define TUNTAP_BUFSIZE 1518

#include "log.h"

/* Generic functions for handling messages */
int handle_message(struct tunnel* tunnel, int socket, char* buf, int length, struct client_opts opts)
{
	char* bufmax = buf + length ;
	while (buf < bufmax) {
		switch (*buf) {
			case C_CONNECT_OK:
				buf = handle_okconnect(tunnel, socket, ++buf, opts) ;
				if (buf == NULL) {
					trace(LOG_ERR, "Unable to decode TCP message") ;
				}
				break ;
			case C_KEEPALIVE:
                trace(LOG_DEBUG, "Received keepalive") ; 
				gettimeofday(&(tunnel->last_keepalive), NULL);				
				buf++ ;
				//keepalive(socket) ;
				break ;
			default :
				trace(LOG_ERR, "Unexpected %d in command\n", *buf) ;
				buf++ ;
		}
	}
	return 0 ;
}

/* Send connection request */
int client_connect(struct tunnel tunnel, int socket)
{
	char command[1] = { C_CONNECT } ;
	trace(LOG_DEBUG, "Emit connect message") ;
	/* Emit a simple connect message */
	return send(socket, command, 1 ,0) ;
}

/* Handler of okconnect message from server */
char* handle_okconnect(struct tunnel* tunnel, int socket, char* tlv, struct client_opts opts)
{
	int tun, raw ;
	int tun_itf_id ;
	struct in_addr debug_addr;
	pthread_t tunnel_thread ;
	struct tunnel_params tp ;
	char message[1] = { C_CONNECT_DONE } ;
	char* newbuf ;

	int pid ;
	int status ;

	/* Parse options received in tlv form from the server */
	newbuf = parse_connect(tlv, &tp) ;
	if (newbuf == NULL) {
		return NULL ;
	}

	/* Tunnel definition */
	debug_addr.s_addr = tp.local_address ;
	trace(LOG_DEBUG, "Creation of tunnel, local address : %s\n", inet_ntoa(debug_addr)) ;

	/* set tun */
	tun = create_tun(opts.tun_name, &tun_itf_id) ;
    if (tun < -1) {
        trace(LOG_ERR, "Unable to create TUN device") ;
        return NULL ;
    }
	set_ip4(tun_itf_id, tp.local_address, 24) ;
	tunnel->tun = tun ; /* real tun device */
	tunnel->fake_tun[0] = -1 ;
	tunnel->fake_tun[1] = -1 ;

    /* set RAW  */
    raw = create_raw() ;
    if (raw < -1) {
        trace(LOG_ERR, "Unable to create RAW socket") ;
        return NULL ;
    }
	tunnel->raw_socket  = raw ;
	tunnel->fake_raw[0] = -1 ;
	tunnel->fake_raw[1] = -1 ;

	/* set params */
	tunnel->params = tp ;

	/* up script */
	if (strcmp(opts.up_script_path, "") != 0) {
		if ((pid = fork()) == 0) {
			char* argv[4] = { "sh", "-c", opts.up_script_path, NULL} ;

			setenv("ifconfig_local", inet_ntoa(debug_addr), 1) ;
			execve("/bin/sh", argv, __environ) ;
		}			

		if (waitpid(pid, &status, 0) < 0) {
			trace(LOG_ERR, "Unable to start up script") ;
		} else {
			if (status == 0) {
				trace(LOG_INFO, "%s sucessfully executed", opts.up_script_path) ;
			} else {
				trace(LOG_WARNING, "%s return code : %d", opts.up_script_path, status) ;
			}
		}
	}
 
    /* Go thread, go ! */
	pthread_create(&tunnel_thread, NULL, new_tunnel, (void*)tunnel) ;

	send(socket, message, 1, 0) ;

	return newbuf ;
}

