/* 
client.c -- Implements client side of the ROHC IP-IP tunnel

The client will initiate the TCP connection and maintain it
while alive.

The sequence is as described below :
 * Initialization of the TCP socket
 * Connection request on TCP socket (message with C_CONNECT)
 * When C_CONNECTOK received, with server parameters, create the
   raw socket, the tun and initialize a rohc_tunnel
 * Answer keepalive message of the server with a keepalive message.

Returns :
 * 0 : Finished successfully (SIG*)
 * 1 : Server disconnected
 * 2 : Unable to connect
*/

#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include "log.h"
int log_max_priority = LOG_INFO;

#include "messages.h"

void usage(char* arg0) {
	printf("Usage : %s --remote addr --dev itf_name  [opts]\n", arg0) ;
	printf("\n") ;
	printf("Options : \n") ;
	printf(" --remote : Address of the remote server \n") ;
	printf(" --port : Port of the remote server \n") ;
	printf(" --dev : Name of the TUN interface that will be created \n") ;
	printf(" --debug : Enable debuging \n") ;
	printf(" --up : Path to a shell script that will be executed when network is up\n") ;
	exit(2) ;
}

int main(int argc, char *argv[])
{
	struct tunnel tunnel ;
    uint32_t serv_addr = 0 ;
    int      port  = 1989;
    char buf[1024] ;
	int sock ;
	int c;

	struct in_addr serv;
	size_t len ;

	struct client_opts client_opts ;
	client_opts.tun_name = calloc(32, sizeof(char)) ;
	client_opts.up_script_path = calloc(1024, sizeof(char)) ;

	/* Initialize logger */
	openlog("iprohc_client", LOG_PID | LOG_PERROR, LOG_DAEMON)  ;

	/* 
	 * Parsing options 
	 */

	struct option options[] = {
		{ "dev",    required_argument, NULL, 'i' },
		{ "remote", required_argument, NULL, 'r' },
		{ "port",   required_argument, NULL, 'p' },
		{ "up",     required_argument, NULL, 'u' },
		{ "debug",  no_argument, NULL, 'd' },
		{ "help",   no_argument, NULL, 'h' },
		{NULL, 0, 0, 0}} ;

	do {
		c = getopt_long(argc, argv, "d", options, NULL) ;
		switch (c) {
			case 'd' :
				log_max_priority = LOG_DEBUG ;
				trace(LOG_DEBUG, "Debbuging enabled", optarg) ;
				break;
		}			
	} while (c != -1) ;

	optind = 1 ;
	do {
		c = getopt_long(argc, argv, "i:r:p:u:h", options, NULL) ;
		switch (c) {
			case 'i' :
				trace(LOG_DEBUG, "TUN interface name : %s", optarg) ;
				if (strlen(optarg) >= 32) {
					trace(LOG_ERR, "TUN interface name too long") ;
					exit(1) ;
				}
				strncpy(client_opts.tun_name, optarg, 32) ;
				break;
			case 'r' :
				trace(LOG_DEBUG, "Remote address : %s", optarg) ;
				serv_addr = htonl(inet_network(optarg)) ;
				break;
			case 'p' :
				port = atoi(optarg) ;
				trace(LOG_DEBUG, "Remote port : %d", port) ;
				break ;
			case 'u' :
				trace(LOG_DEBUG, "Up script path: %s", optarg) ;
				if (strlen(optarg) >= 1024) {
					trace(LOG_ERR, "Up script path too long") ;
					exit(1) ;
				}
				strncpy(client_opts.up_script_path, optarg, 1024) ;
				break;
			case 'h' :
				usage(argv[0]) ;
				break;
		}			
	} while (c != -1) ;

	if (serv_addr == 0) {
		trace(LOG_ERR, "Remote address is mandatory") ;
		exit(1) ;
	}

	if (strcmp(client_opts.tun_name, "") == 0) {
		trace(LOG_ERR, "TUN interface name is mandatory") ;
		exit(1) ;
	}

	/* 
	 *	Creation of TCP socket to neogotiate parameters and maintain it
	 */

	sock = socket(AF_INET, SOCK_STREAM, 0) ;
	if (sock < 0) {
		perror("Can't open socket") ;
		exit(1) ;
	}	

	struct	sockaddr_in servaddr ;
	servaddr.sin_family	  = AF_INET;
	servaddr.sin_addr.s_addr = serv_addr;
	servaddr.sin_port		= htons(port);
	trace(LOG_INFO, "Connecting to %s\n", inet_ntoa(servaddr.sin_addr)) ;

	if (connect(sock,  (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		trace(LOG_ERR, "Connection failed : %s", strerror(errno)) ;
		return 2 ;
	}

	/* Set destination tunnel parameter */
	serv.s_addr = serv_addr ;
	tunnel.dest_address = serv ;

	/* Ask for connection */
	client_connect(tunnel, sock) ;

	/* Wait for answer and other messages, close when
	   socket is close */
	while ((len = recv(sock, buf, 1024, 0))) {
		trace(LOG_DEBUG, "Received %ld bytes of data", len) ;
		if (handle_message(&tunnel, sock, buf, len, client_opts) < 0) {
			return 1 ;
		}
	}

	return 0 ;
}
