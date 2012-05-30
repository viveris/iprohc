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
#include "keepalive.h"
#include "messages.h"

#include <unistd.h>
#include <getopt.h>

/* Create TCP socket for communication with server */
int create_tcp_socket(uint32_t address, uint16_t port) 
{

	int sock = socket(AF_INET, SOCK_STREAM, 0) ;

	struct	sockaddr_in servaddr ;
	servaddr.sin_family	  = AF_INET;
	servaddr.sin_addr.s_addr = address;
	servaddr.sin_port		= htons(port);
	trace(LOG_INFO, "Connecting to %s\n", inet_ntoa(servaddr.sin_addr)) ;

	if (connect(sock,  (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		perror("Connect failed") ;
		return -1 ;
	}
	
	return sock ;
}

void usage(char* arg0) {
	printf("Usage : %s --remote addr --dev itf_name  [opts]\n", arg0) ;
	printf("\n") ;
	printf("Options : \n") ;
	printf(" --remote : Address of the remote server \n") ;
	printf(" --port : Port of the remote server \n") ;
	printf(" --dev : Name of the TUN interface that will be created \n") ;
	printf(" --up : Path to a shell script that will be executed when network is up\n") ;
	exit(2) ;
}

int main(int argc, char *argv[])
{
	struct tunnel tunnel ;
    uint32_t serv_addr = 0 ;
    int      port ;
    char buf[1024] ;
	int socket ;
	int c;

	struct in_addr serv;
	size_t len ;

	struct client_opts client_opts ;
	client_opts.tun_name = calloc(32, sizeof(char)) ;
	client_opts.up_script_path = calloc(1024, sizeof(char)) ;

	/* Initialize logger */
	openlog("rohc_ipip_client", LOG_PID | LOG_PERROR, LOG_DAEMON) ;

	/* Parsing options */
	struct option options[] = {
		{ "dev",    required_argument, NULL, 'i' },
		{ "remote", required_argument, NULL, 'r' },
		{ "port",   required_argument, NULL, 'p' },
		{ "up",     required_argument, NULL, 'U' },
		{ "help",   no_argument, NULL, 'h' },
		{NULL, 0, 0, 0}
							  } ;
	int option_index = 0;
	do {
		c = getopt_long(argc, argv, "i:r:p:u:h", options, &option_index) ;
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
	/* Create socket to neogotiate parameters and maintain it */
	socket = create_tcp_socket(serv_addr, 1989) ;
	if (socket < 0) {
		perror("Can't open socket") ;
		exit(1) ;
	}	

	/* Set some tunnel parameters */
	serv.s_addr = serv_addr ;
	tunnel.dest_address = serv ;

	/* Ask for connection */
	client_connect(tunnel, socket) ;

	/* Wait for answer and other messages, close when
	   socket is close */
	while ((len = recv(socket, buf, 1024, 0))) {
		trace(LOG_DEBUG, "Received %ld bytes of data", len) ;
		if (handle_message(&tunnel, socket, buf, len, client_opts) < 0) {
			break ;
		}
	}

	return 0 ;
}
