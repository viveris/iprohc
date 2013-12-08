/*
This file is part of iprohc.

iprohc is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.

iprohc is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with iprohc.  If not, see <http://www.gnu.org/licenses/>.
*/

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

#include "config.h"

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
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>

#include "log.h"
int log_max_priority = LOG_INFO;
bool iprohc_log_stderr = true;

#include "messages.h"
#include "tls.h"


static void usage(void)
{
	printf("IP/ROHC client: establish a tunnel with an instance of IP/ROHC server\n"
	       "\n"
	       "You must be root to run the IP/ROHC tunnel client.\n"
	       "\n"
	       "Usage: iprohc_client -r remoteaddr -b itfname -i itfname -P pkcs12file [options]\n"
	       "   or: iprohc_client -h|--help\n"
	       "   or: iprohc_client -v|--version\n"
	       "\n"
	       "Options:\n"
	       "Mandatory options:\n"
	       "  -b, --basedev ITF   The name of the underlying interface\n"
	       "  -i, --dev ITF       The name of the interface that will be\n"
	       "                      created\n"
	       "  -P, --p12 PATH      The path to the PKCS#12 file containing\n"
	       "                      server CA, client key and client crt\n"
	       "  -r, --remote ADDR   The address of the remote server\n"
	       "\n"
	       "Other options:\n"
	       "  -d, --debug         Enable debuging\n"
	       "  -h, --help          Print this help message\n"
	       "  -k, --packing NUM   Override packing level sent by server\n"
	       "  -p, --port NUM      The port of the remote server\n"
	       "  -u, --up PATH       Path to a shell script that will be run\n"
	       "                      when tunnel is ready\n"
	       "  -v, --version       Print the software version\n"
	       "\n"
	       "Examples:\n"
	       "\n"
	       "Establish an IP/ROHC tunnel with remote server located at 192.168.1.14\n"
	       "through the local network interface eth0:\n"
	       "  iprohc_client -r 192.168.1.14 -b eth0 -i iprohc -P ./client.p12\n"
	       "\n"
	       "Establish an IP/ROHC tunnel with server 10.2.5.3 through the local\n"
	       "network interface eth2 and run the ./set_routes.sh script once tunnel\n"
	       "is established:\n"
	       "  iprohc_client -r 10.2.5.3 -b eth2 -i iprohc -P ./certificate \\\n"
	       "                -u ./set_routes.sh\n"
	       "\n"
	       "Print software version:\n"
	       "  iprohc_client --version\n"
	       "\n"
	       "Print usage help:\n"
	       "  iprohc_client --help\n"
	       "\n"
	       "Report bugs to <%s>.\n",
	       PACKAGE_BUGREPORT);
}


int alive;
void sigterm(int signal)
{
	alive = 0;
}


int main(int argc, char *argv[])
{
	int exit_status = 1;
	struct tunnel tunnel;
	char serv_addr[1024];
	struct sockaddr_in local_addr;
	socklen_t local_addr_len;
	char port[6]  = {'3','1','2','6', '\0', '\0'};
	unsigned char buf[1024];
	int sock;
	int c;

	char pkcs12_f[1024];
	gnutls_session_t session;
	gnutls_certificate_credentials_t xcred;
	unsigned int verify_status;

	int ret;
	bool is_ok;

	struct client_opts client_opts;

	memset(client_opts.tun_name, 0, IFNAMSIZ);
	memset(client_opts.basedev, 0, IFNAMSIZ);
	client_opts.up_script_path = calloc(1024, sizeof(char));
	client_opts.packing = 0;
	serv_addr[0] = '\0';
	pkcs12_f[0] = '\0';

	/* Initialize logger */
	openlog("iprohc_client", LOG_PID, LOG_DAEMON);


	/*
	 * Parsing options
	 */

	struct option options[] = {
		{ "dev",     required_argument, NULL, 'i' },
		{ "basedev", required_argument, NULL, 'b' },
		{ "remote",  required_argument, NULL, 'r' },
		{ "port",    required_argument, NULL, 'p' },
		{ "p12",     required_argument, NULL, 'P' },
		{ "packing", required_argument, NULL, 'k' },
		{ "up",      required_argument, NULL, 'u' },
		{ "debug",   no_argument, NULL, 'd' },
		{ "help",    no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{NULL, 0, 0, 0}
	};

	do
	{
		c = getopt_long(argc, argv, "i:b:r:p:u:P:hvk:d", options, NULL);
		switch(c)
		{
			case 'd':
				log_max_priority = LOG_DEBUG;
				trace(LOG_DEBUG, "Debbuging enabled");
				break;
		}
	}
	while(c != -1);

	optind = 1;
	do
	{
		c = getopt_long(argc, argv, "i:b:r:p:u:P:hvk:d", options, NULL);
		switch(c)
		{
			case 'i':
				trace(LOG_DEBUG, "TUN interface: %s", optarg);
				if(strlen(optarg) >= IFNAMSIZ)
				{
					trace(LOG_ERR, "TUN interface name too long");
					goto error;
				}
				strncpy(client_opts.tun_name, optarg, IFNAMSIZ);
				break;
			case 'b':
				trace(LOG_DEBUG, "underlying interface: %s", optarg);
				if(strlen(optarg) >= IFNAMSIZ)
				{
					trace(LOG_ERR, "underlying interface name too long");
					goto error;
				}
				if(if_nametoindex(optarg) <= 0)
				{
					trace(LOG_ERR, "underlying interface '%s' does not exist",
					      optarg);
					goto error;
				}
				strncpy(client_opts.basedev, optarg, IFNAMSIZ);
				break;
			case 'r':
				trace(LOG_DEBUG, "Remote address : %s", optarg);
				strncpy(serv_addr, optarg, 1024);
				serv_addr[1023] = '\0';
				break;
			case 'p':
				strncpy(port, optarg, 6);
				port[5] = '\0';
				trace(LOG_DEBUG, "Remote port : %s", port);
				break;
			case 'P':
				strncpy(pkcs12_f, optarg, 1024);
				pkcs12_f[1023] = '\0';
				trace(LOG_DEBUG, "PKCS12 file : %s",  pkcs12_f);
				break;
			case 'u':
				trace(LOG_DEBUG, "Up script path: %s", optarg);
				if(strlen(optarg) >= 1024)
				{
					trace(LOG_ERR, "Up script path too long");
					goto error;
				}
				strncpy(client_opts.up_script_path, optarg, 1024);
				break;
			case 'k':
				client_opts.packing = atoi(optarg);
				trace(LOG_DEBUG, "Using forced packing : %d\n", client_opts.packing);
				break;
			case 'h':
				usage();
				goto error;
			case 'v':
				printf("IP/ROHC client, version %s%s\n", PACKAGE_VERSION,
				       PACKAGE_REVNO);
				goto error;
		}
	}
	while(c != -1);

	if(strcmp(serv_addr, "") == 0)
	{
		trace(LOG_ERR, "wrong usage: remote address is mandatory, "
		      "use the --remote or -r option to specify it");
		goto error;
	}

	if(strcmp(client_opts.tun_name, "") == 0)
	{
		trace(LOG_ERR, "wrong usage: TUN interface name is mandatory, "
		      "use the --dev or -i option to specify it");
		goto error;
	}

	if(strcmp(client_opts.basedev, "") == 0)
	{
		trace(LOG_ERR, "wrong usage: underlying interface name is mandatory, "
		      "use the --basedev or -b option to specify it");
		goto error;
	}

	if(strcmp(pkcs12_f, "") == 0)
	{
		trace(LOG_ERR, "PKCS12 file required");
		trace(LOG_ERR, "wrong usage: PKCS12 file is mandatory, "
		      "use the --p12 or -P option to specify it");
		goto error;
	}


	/*
	 * GnuTLS stuff
	 */

	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&xcred);
	ret = load_p12(xcred, pkcs12_f, NULL);
	if(ret < 0)
	{
		/* Try with empyty password */
		ret = load_p12(xcred, pkcs12_f, "");
		if(ret < 0)
		{
			trace(LOG_ERR, "Unable to load certificate : %s", gnutls_strerror(ret));
			goto error;
		}
	}

	gnutls_init(&session, GNUTLS_CLIENT);
	/* const char* err ;
	   gnutls_priority_set_direct(session, "NORMAL", &err); // NEW API */
	const int protocol_priority[] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };
	const int kx_priority[] = { GNUTLS_KX_RSA, 0 };
	const int cipher_priority[] = { GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR, 0};
	const int comp_priority[] = { GNUTLS_COMP_ZLIB, GNUTLS_COMP_NULL, 0 };
	const int mac_priority[] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
	gnutls_protocol_set_priority(session, protocol_priority);
	gnutls_cipher_set_priority(session, cipher_priority);
	gnutls_compression_set_priority(session, comp_priority);
	gnutls_kx_set_priority(session, kx_priority);
	gnutls_mac_set_priority(session, mac_priority);

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);


	/*
	 * DNS query
	 */

	struct addrinfo *result, *rp;
	struct addrinfo hints;
	int s;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;    /* Allow IPv4 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;           /* Any protocol */

	s = getaddrinfo(serv_addr, port, &hints, &result);
	if(s != 0)
	{
		trace(LOG_ERR, "Unable to connect to %s : %s", serv_addr, gai_strerror(s));
		goto error;
	}


	/*
	 * Creation of TCP socket to negotiate parameters and maintain it
	 */
	if(result == NULL) /* no address available */
	{
		trace(LOG_ERR, "failed connect to server: no address available");
		goto error;
	}
	for(rp = result; rp != NULL; rp = rp->ai_next)
	{
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(sock < 0)
		{
			continue;
		}

		if(connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
		{
			break;                  /* Success */
		}
		close(sock);
	}
	if(rp == NULL || sock < 0) /* no address succeeded */
	{
		trace(LOG_ERR, "failed to connect to server: %s (%d)",
				strerror(errno), errno);
		goto close_tcp;
	}

	/* retrieve the local address and port used to contact the server
	 * (will be used to filter ingress data traffic later on) */
	local_addr_len = sizeof(struct sockaddr_in);
	memset(&local_addr, 0, local_addr_len);
	ret = getsockname(sock, (struct sockaddr *) &local_addr, &local_addr_len);
	if(ret != 0)
	{
		trace(LOG_ERR, "failed to determine the local IP address used to "
				"contact the server: %s (%d)", strerror(errno), errno);
		goto close_tcp;
	}
	tunnel.src_address.s_addr = ntohl(local_addr.sin_addr.s_addr);
	trace(LOG_INFO, "local address %u.%u.%u.%u:%u is used to contact server",
			(tunnel.src_address.s_addr >> 24) & 0xff,
			(tunnel.src_address.s_addr >> 16) & 0xff,
			(tunnel.src_address.s_addr >>  8) & 0xff,
			(tunnel.src_address.s_addr >>  0) & 0xff,
			ntohs(local_addr.sin_port));


	/* stop writing logs on stderr */
	iprohc_log_stderr = false;


	/*
	 * TLS handshake
	 */

	/* Get rid of warning, it's a "bug" of GnuTLS
	 * (cf. http://lists.gnu.org/archive/html/help-gnutls/2006-03/msg00020.html) */
	gnutls_transport_set_ptr_nowarn(session, sock);
	do
	{
		ret = gnutls_handshake(session);
	}
	while(ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if(ret < 0)
	{
		trace(LOG_ERR, "TLS handshake failed : %s", gnutls_strerror(ret));
		exit_status = 2;
		goto close_tls;
	}
	trace(LOG_INFO, "TLS handshake succeeded");

	if(gnutls_certificate_verify_peers2(session, &verify_status) < 0)
	{
		trace(LOG_ERR, "TLS verify failed : %s", gnutls_strerror(ret));
		exit_status = -3;
		goto close_tls;
	}

	if((verify_status & GNUTLS_CERT_INVALID) &&
	   (verify_status != (GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID)))
	{
		trace(LOG_ERR, "certificate cannot be verified (status %u)",
		      verify_status);
		if(verify_status & GNUTLS_CERT_REVOKED)
		{
			trace(LOG_ERR, " - Revoked certificate");
		}
		if(verify_status & GNUTLS_CERT_SIGNER_NOT_FOUND)
		{
			trace(LOG_ERR, " - Unable to trust certificate issuer");
		}
		if(verify_status & GNUTLS_CERT_SIGNER_NOT_CA)
		{
			trace(LOG_ERR, " - Certificate issuer is not a CA");
		}
#ifdef GNUTLS_CERT_NOT_ACTIVATED
		if(verify_status & GNUTLS_CERT_NOT_ACTIVATED)
		{
			trace(LOG_ERR, " - The certificate is not activated");
		}
#endif
#ifdef GNUTLS_CERT_EXPIRED
		if(verify_status & GNUTLS_CERT_EXPIRED)
		{
			trace(LOG_ERR, " - The certificate has expired");
		}
#endif
		exit_status = -3;
		goto close_tls;
	}
	trace(LOG_INFO, "client certificate accepted");

	client_opts.socket = sock;
	client_opts.tls_session = session;

	/* Set destination tunnel parameter */
	tunnel.dest_address = ((struct sockaddr_in*) rp->ai_addr)->sin_addr;
	memset(&(tunnel.dest_addr_str), 0, INET_ADDRSTRLEN);

	/* Ask for connection */
	unsigned char command[1024];
	size_t command_len;
	size_t tlv_len;

	command[0] = C_CONNECT;
	command_len = 1;

	trace(LOG_INFO, "send connect message to server");
	is_ok = gen_connrequest(client_opts.packing, command + 1, &tlv_len);
	if(!is_ok)
	{
		trace(LOG_ERR, "failed to generate the connect messsage for server");
		goto close_tls;
	}
	command_len += tlv_len;

	/* Emit a simple connect message */
	size_t emitted_len = 0;
	do
	{
		ret = gnutls_record_send(session, command + emitted_len,
		                         command_len - emitted_len);
		if(ret < 0)
		{
			trace(LOG_ERR, "failed to send message to server over TLS (%d)", ret);
			goto close_tls;
		}
		emitted_len += ret;
	}
	while(emitted_len < command_len);

	/* Handle SIGTERM */
	signal(SIGTERM, sigterm);
	signal(SIGINT, sigterm);

	/* Wait for answer and other messages, close when socket is close */
	trace(LOG_INFO, "wait for connect answer from server");
	alive = 1;
	while(alive)
	{
		struct timeval timeout;
		fd_set rdfs;

		timeout.tv_sec = 80;
		timeout.tv_usec = 0;

		FD_ZERO(&rdfs);
		FD_SET(sock, &rdfs);

		ret = select(sock + 1, &rdfs, NULL, NULL, &timeout);
		if(ret < 0)
		{
			if(errno == EINTR)
			{
				/* interrupted by a signal */
				continue;
			}
			trace(LOG_ERR, "select failed: %s (%d)", strerror(errno), errno);
			goto close_tls;
		}
		else if(ret == 0)
		{
			/* timeout reached */
			trace(LOG_WARNING, "timeout reached while waiting to message "
			      "on TCP connection, give up");
			goto close_tls;
		}

		if(FD_ISSET(sock, &rdfs))
		{
			ret = gnutls_record_recv(session, buf, 1024);
			if(ret < 0)
			{
				trace(LOG_ERR, "failed to receive data from server on TLS "
				      "session: %s (%d)", gnutls_strerror(ret), ret);
				goto error;
			}
			else if(ret == 0)
			{
				trace(LOG_ERR, "TLS session was interrupted by server");
				goto error;
			}
			if(!handle_message(&tunnel, buf, ret, client_opts))
			{
				trace(LOG_ERR, "failed to handle message received from server");
				goto error;
			}
		}
	}

	trace(LOG_INFO, "client interrupted, interrupt established session");

	/* send disconnect message to server */
	if(!client_send_disconnect_msg(session))
	{
		trace(LOG_WARNING, "failed to cleanly close the session with server");
	}

	exit_status = 0;

close_tls:
	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(xcred);
	gnutls_global_deinit();
close_tcp:
	close(sock);
error:
	return exit_status;
}
