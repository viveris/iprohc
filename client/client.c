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
#include <signal.h>
#include <gnutls/gnutls.h>

#include "log.h"
int log_max_priority = LOG_INFO;

#include "messages.h"
#include "tls.h"

void usage(char* arg0) {
	printf("Usage : %s --remote addr --dev itf_name  [opts]\n", arg0) ;
	printf("\n") ;
	printf("Options : \n") ;
	printf(" --remote : Address of the remote server \n") ;
	printf(" --port : Port of the remote server \n") ;
	printf(" --dev : Name of the TUN interface that will be created \n") ;
	printf(" --debug : Enable debuging \n") ;
	printf(" --up : Path to a shell script that will be executed when network is up\n") ;
	printf(" --p12 : Path to the pkcs12 file containing server CA, client key and client crt\n") ;
	printf(" --packing : Override packing\n") ;
	exit(2) ;
}

int alive ;
void sigterm(int signal)
{
	alive = 0 ;
}

int main(int argc, char *argv[])
{
	struct tunnel tunnel ;
    uint32_t serv_addr = 0 ;
    int      port  = 3126;
    char buf[1024] ;
	int sock ;
	int c;

	struct in_addr serv;
	size_t len ;

	char pkcs12_f[1024] ;
	gnutls_session_t session;
	gnutls_certificate_credentials_t xcred;
	unsigned int verify_status ;

	int ret ;

	struct client_opts client_opts ;
	client_opts.tun_name = calloc(32, sizeof(char)) ;
	client_opts.up_script_path = calloc(1024, sizeof(char)) ;
	client_opts.packing = 0 ;

	fd_set rdfs;

	/* Initialize logger */
	openlog("iprohc_client", LOG_PID | LOG_PERROR, LOG_DAEMON)  ;

	/* Handle SIGTERM */
	signal(SIGTERM, sigterm) ;
	signal(SIGINT, sigterm) ;

	/* 
	 * Parsing options 
	 */

	struct option options[] = {
		{ "dev",    required_argument, NULL, 'i' },
		{ "remote", required_argument, NULL, 'r' },
		{ "port",   required_argument, NULL, 'p' },
		{ "p12",    required_argument, NULL, 'P' },
		{ "packing", required_argument, NULL, 'k' },
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
		c = getopt_long(argc, argv, "i:r:p:u:P:hk:", options, NULL) ;
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
            case 'P' :
				strncpy(pkcs12_f, optarg, 1024) ;
				pkcs12_f[1023] = '\0' ;
				trace(LOG_DEBUG, "PKCS12 file : %s",  pkcs12_f) ;
                break ;
			case 'u' :
				trace(LOG_DEBUG, "Up script path: %s", optarg) ;
				if (strlen(optarg) >= 1024) {
					trace(LOG_ERR, "Up script path too long") ;
					exit(1) ;
				}
				strncpy(client_opts.up_script_path, optarg, 1024) ;
				break;
			case 'k' :
				client_opts.packing = atoi(optarg) ;
				trace(LOG_DEBUG, "Using forced packing : %d\n", client_opts.packing) ;
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

    if (strcmp(pkcs12_f, "") == 0) {
		trace(LOG_ERR, "PKCS12 file required") ;
		exit(1) ;
	}
    /*
     * GnuTLS stuff
	 */

	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&xcred) ;
	ret = load_p12(xcred, pkcs12_f, NULL) ;
	if (ret < 0) {
		/* Try with empyty password */
		ret = load_p12(xcred, pkcs12_f, "") ;
	}

	if (ret < 0) {
		trace(LOG_ERR, "Unable to load certificate : %s", gnutls_strerror(ret)) ;
		exit(1) ;
	}


	gnutls_init(&session, GNUTLS_CLIENT);
	/* const char* err ;
	   gnutls_priority_set_direct(session, "NORMAL", &err); // NEW API */
    const int protocol_priority[] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };
    const int kx_priority[] = { GNUTLS_KX_RSA, 0 };
    const int cipher_priority[] = { GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR, 0};
    const int comp_priority[] = { GNUTLS_COMP_ZLIB, GNUTLS_COMP_NULL, 0 };
    const int mac_priority[] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
	gnutls_protocol_set_priority(session, protocol_priority) ;
    gnutls_cipher_set_priority(session, cipher_priority);
    gnutls_compression_set_priority(session, comp_priority);
    gnutls_kx_set_priority(session, kx_priority);
    gnutls_mac_set_priority(session, mac_priority);

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

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

	/*
	 * TLS handshake
	 */
	
	/* Get rid of warning, it's a "bug" of GnuTLS (cf http://lists.gnu.org/archive/html/help-gnutls/2006-03/msg00020.html) */
	gnutls_transport_set_ptr_nowarn(session, sock);

	do {
		ret = gnutls_handshake(session);
    } while (ret < 0 && gnutls_error_is_fatal (ret) == 0);	

	if (ret < 0) {
		trace(LOG_ERR, "TLS handshake failed : %s", gnutls_strerror(ret)) ;
		gnutls_deinit(session);
		close(sock) ;	
		return 2 ;
	}
	trace(LOG_INFO, "TLS handshake succeeded") ;

    if (gnutls_certificate_verify_peers2(session, &verify_status) < 0) {
        trace(LOG_ERR, "TLS verify failed : %s", gnutls_strerror(ret)) ;
        return -3 ;
    }
    
    if  (verify_status & GNUTLS_CERT_INVALID 
     && (verify_status != (GNUTLS_CERT_INSECURE_ALGORITHM|GNUTLS_CERT_INVALID))
        ) {
        trace(LOG_ERR, "Certificate can't be verified : ") ;
        if (verify_status & GNUTLS_CERT_REVOKED)
            trace(LOG_ERR, " - Revoked certificate") ;
        if (verify_status & GNUTLS_CERT_SIGNER_NOT_FOUND)
            trace(LOG_ERR, " - Unable to trust certificate issuer") ;
        if (verify_status & GNUTLS_CERT_SIGNER_NOT_CA)
            trace(LOG_ERR, " - Certificate issue is not a CA") ;
#ifdef GNUTLS_CERT_NOT_ACTIVATED
        if (verify_status & GNUTLS_CERT_NOT_ACTIVATED)
            trace(LOG_ERR, " - The certificate is not activated") ;
#endif
#ifdef GNUTLS_CERT_EXPIRED
        if (verify_status & GNUTLS_CERT_EXPIRED)
            trace(LOG_ERR, " - The certificate has expired") ;
#endif
        return -3 ;
    }
	
	client_opts.socket = sock ;
	client_opts.tls_session = session ;

	/* Set destination tunnel parameter */
	serv.s_addr = serv_addr ;
	tunnel.dest_address = serv ;

	/* Ask for connection */
    char command[1] = { C_CONNECT } ;
	trace(LOG_DEBUG, "Emit connect message") ;
	/* Emit a simple connect message */
	gnutls_record_send(session, command, 1) ;

	/* Wait for answer and other messages, close when
	   socket is close */
	alive = 1 ;
	while (alive) {
		FD_ZERO(&rdfs);
		FD_SET(sock, &rdfs);
		if (pselect(sock+1, &rdfs, NULL, NULL, NULL, NULL) < 0) {
            break ;
        }
		if (FD_ISSET(sock, &rdfs)) {
			len = gnutls_record_recv(session, buf, 1024) ;
			if (handle_message(&tunnel, buf, len, client_opts) < 0) {
				return 1 ;
			}
		} 
	}
	trace(LOG_INFO, "Interupted, exiting") ;

	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(xcred);
	gnutls_global_deinit();

	return 0 ;
}
