/* client.c -- Implements client side of the ROHC IP-IP tunnel
*/

#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#define MAX_LOG LOG_INFO
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)

#include "tlv.h"
#include "messages.h"

/* Create TCP socket for communication with server */
int create_tcp_socket(uint32_t address, uint16_t port) {

	int sock = socket(AF_INET, SOCK_STREAM, 0) ;

	struct	sockaddr_in servaddr ;
	servaddr.sin_family	  = AF_INET;
	servaddr.sin_addr.s_addr = address;
	servaddr.sin_port		= htons(port);
	trace(LOG_INFO, "Connecting to %s\n", inet_ntoa(servaddr.sin_addr)) ;

	if (connect(sock,  (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
		perror("Connect failed") ;
	
	return sock ;
}

int handle_message(struct tunnel* tunnel, char* buf, int length)
{
	char* bufmax = buf + length ;
	while (buf < bufmax) {
		switch (*buf) {
			case C_CONNECT_OK:
				buf = handle_okconnect(tunnel, ++buf) ;
				if (buf == NULL) {
					trace(LOG_ERR, "Unable to decode TCP message") ;
				}
				break ;
			default :
				trace(LOG_ERR, "Unexpected %d in command\n", *buf) ;
				return -1 ;
		}
	}
	return 0 ;
}

int main(int argc, char *argv[]) {

	struct tunnel tunnel ;
    uint32_t serv_addr ;
    char buf[1024] ;
	int socket ;

	struct in_addr serv;
	size_t len ;

	/* Initialize logger */
	openlog("rohc_ipip_client", LOG_PID | LOG_PERROR, LOG_DAEMON) ;

	/* Create socket to neogotiate parameters and maintain it */
    serv_addr = htonl(inet_network(argv[1])) ;
	socket = create_tcp_socket(serv_addr, 1989) ;
	if (socket < 0) {
		perror("Can't open socket") ;
		exit(1) ;
	}	

	/* Set some tunnel parameters */
	tunnel.tcp_socket = socket ;
	serv.s_addr = serv_addr ;
	tunnel.dest_address = serv ;

	/* Ask for connection */
	client_connect(tunnel) ;

	/* Wait for answer and other messages, close when
	   socket is close */
	while ((len = recv(socket, buf, 1024, 0))) {
		trace(LOG_DEBUG, "Received %ld bytes of data", len) ;
		trace(LOG_DEBUG, "%s", buf) ;
		if (handle_message(&tunnel, buf, len) < 0) {
			break ;
		}
	}

	return 0 ;
}
