/* client.c -- Implements client side of the ROHC IP-IP tunnel
*/


#include <sys/socket.h> 
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
#include <syslog.h>

#include "rohc_tunnel.h"
#include "tun_helpers.h"

#define TUNTAP_BUFSIZE 1518

#define MAX_LOG LOG_INFO
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)

/* Create TCP socket for communication with server */
int create_tcp_socket(uint32_t address, uint16_t port) {

	int sock = socket(AF_INET, SOCK_STREAM, 0) ;

	struct	sockaddr_in servaddr ;
	servaddr.sin_family	  = AF_INET;
	servaddr.sin_addr.s_addr = address;
	servaddr.sin_port		= htons(port);

	if (connect(sock,  (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
		perror("Connect failed") ;
	
	return sock ;
}

int main(int argc, char *argv[]) {

    uint32_t serv_addr ;
	int tun ;
	int tun_itf_id ;
	struct in_addr serv;
	struct in_addr local;
	struct tunnel tunnel ;
	int socket ;

	/* Initialize logger */
	openlog("rohc_ipip_client", LOG_PID | LOG_PERROR, LOG_DAEMON) ;

	/* Create socket to neogotiate parameters */
    serv_addr = htonl(inet_network("10.0.2.212")) ;
	socket = create_tcp_socket(serv_addr, 1989) ;
	if (socket < 0) {
		perror("Can't open socket") ;
		exit(1) ;
	}	

	/* Tun creation */
	tun = create_tun("tun42", &tun_itf_id) ;
	set_ip4(tun_itf_id, 392407232, 24) ; /* 192.168.99.23/24 */

	/* Tunnel definition */
	trace(LOG_DEBUG, "Creation of tunnel") ;

	/* dest addr */
	serv.s_addr = serv_addr ;
	tunnel.dest_address = serv ;

	/* local_addr */
	local.s_addr = htonl(inet_network("192.168.99.23")) ;
	tunnel.local_address = local ;

	/* set tun */
	tunnel.tun = tun ; /* real tun device */
	tunnel.fake_tun[0] = -1 ;
	tunnel.fake_tun[1] = -1 ;
 
	/* Go go go ! */
	new_tunnel(&tunnel) ;

	return 1 ;
}
