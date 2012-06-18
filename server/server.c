/* server.c -- Implements server side of the ROHC IP-IP tunnel
*/

#include <sys/socket.h> 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <getopt.h>

#include "tun_helpers.h"

#include "client.h"
#include "messages.h"

// XXX : Config ?
#define MAX_CLIENTS 50

/// The maximal size of data that can be received on the virtual interface
#define TUNTAP_BUFSIZE 1518

#include "log.h"
int log_max_priority = LOG_DEBUG;

/* List of clients */
struct client** clients ; 

/* 
 * Route function that will be threaded twice to route
 * from tun to fake_tun and from raw to fake_raw 
*/
enum type_route { TUN, RAW } ;

struct route_args {
	int fd ;
	struct client** clients ;
	enum type_route type ;
} ;

/* Thread that will be called to monitor tun or raw and route */
void* route(void* arg)
{
	/* Getting args */
	int fd = ((struct route_args *)arg)->fd ;
	struct client** clients = ((struct route_args *)arg)->clients ;
	enum type_route type = ((struct route_args *)arg)->type ;

	int i ;
	int ret;
    static unsigned char buffer[TUNTAP_BUFSIZE];
    unsigned int buffer_len = TUNTAP_BUFSIZE;

	struct in_addr addr;

	uint32_t* src_ip ;
	uint32_t* dest_ip ;
	
	trace(LOG_INFO, "Initializing routing thread\n") ;

	while ((ret = read(fd, buffer, buffer_len))) {
		if(ret < 0 || ret > buffer_len)
		{
			trace(LOG_ERR, "read failed: %s (%d)\n", strerror(errno), errno);
			return NULL ;
		}

		trace(LOG_DEBUG, "Read %d bytes\n", ret) ;
		/* Get packet destination IP if tun or source IP if raw */
		if (type == TUN) {
			dest_ip = (uint32_t*) &buffer[20];
			addr.s_addr = *dest_ip ;
			trace(LOG_DEBUG, "Packet destination : %s\n", inet_ntoa(addr)) ;
		} else {
			src_ip = (uint32_t*) &buffer[12];
			addr.s_addr = *src_ip ;
			trace(LOG_DEBUG, "Packet source : %s\n", inet_ntoa(addr)) ;
		}

		for (i=0; i < MAX_CLIENTS; i++) {
			/* Find associated client */
			if (clients[i] != NULL) {
				/* Send to fake raw or tun device */
				if (type == TUN) {
					if (addr.s_addr == clients[i]->local_address.s_addr) {
						write(clients[i]->tunnel.fake_tun[1], buffer, ret) ;
						break ;
					}
				} else {
					if (addr.s_addr == clients[i]->tunnel.dest_address.s_addr) {
						write(clients[i]->tunnel.fake_raw[1], buffer, ret) ;
					}
					break ;
				}
			}
		}
	}

	return NULL ;
}

void dump_stats_client(struct client* client) {
    trace(LOG_NOTICE, "------------------------------------------------------") ;
    trace(LOG_NOTICE, "Client %s", inet_ntoa(client->tunnel.dest_address)) ;
    trace(LOG_NOTICE, "Stats : ") ;
    trace(LOG_NOTICE, " . Failed decompression : %d", client->tunnel.stats.decomp_failed) ;
    trace(LOG_NOTICE, " . Total  decompression : %d", client->tunnel.stats.decomp_total) ;
    trace(LOG_NOTICE, " . Failed compression   : %d", client->tunnel.stats.comp_failed) ;
    trace(LOG_NOTICE, " . Total  compression   : %d", client->tunnel.stats.comp_total) ;
    trace(LOG_NOTICE, " . Failed depacketization        : %d", client->tunnel.stats.unpack_failed) ;
    trace(LOG_NOTICE, " . Total received packets on raw : %d", client->tunnel.stats.total_received) ;
    trace(LOG_NOTICE, " . Total compressed header size  : %d bytes", client->tunnel.stats.head_comp_size) ;
    trace(LOG_NOTICE, " . Total compressed packet size  : %d bytes", client->tunnel.stats.total_comp_size) ;
    trace(LOG_NOTICE, " . Total header size before comp : %d bytes", client->tunnel.stats.head_uncomp_size) ;
    trace(LOG_NOTICE, " . Total packet size before comp : %d bytes", client->tunnel.stats.total_uncomp_size) ;
}

/*
 * Fonction called on SIGUSR1 to dump statistics to log
 */
void dump_stats(int sig)
{
    int j ;

    for (j=0; j<MAX_CLIENTS; j++) {
        if (clients[j] != NULL && clients[j]->tunnel.alive >= 0) {
            dump_stats_client(clients[j]) ;
        }
    }
}

/*
 * Fonction called on SIGUSR2 to switch between LOG_INFO and LOG_DEBUG for log_max_priority
 */
void switch_log_max(int sig)
{
	if (log_max_priority == LOG_DEBUG) {
		log_max_priority = LOG_INFO ;
        trace(LOG_INFO, "Debugging disabled") ;
	} else {
		log_max_priority = LOG_DEBUG ;
        trace(LOG_DEBUG, "Debugging enabled") ;
	}
}

void usage(char* arg0) {
    printf("Usage : %s [opts]\n", arg0) ;
    printf("\n") ;
    printf("Options : \n") ;
    printf(" --port    : Port to listen on (default: 1989)\n") ;
    printf(" --pidfile : Path to the pid file\n") ;
    exit(2) ;
}

int alive ;
void quit(int sig) {
	alive = 0;
}

int main(int argc, char *argv[])
{

	int serv_socket ;

	int tun, raw ;
	int tun_itf_id ;

	struct route_args route_args_tun ;
	struct route_args route_args_raw ;
	pthread_t route_thread; 

	fd_set rdfs;
	int max ;
	int j ;

	int ret ;
	sigset_t sigmask;

	int address = INADDR_ANY ;
	int port    = 1989       ;

	char pidfile_path[1024] ;
	pidfile_path[0] = '\0' ;
	FILE* pid = NULL ;
	
	int c;

	clients = calloc(MAX_CLIENTS, sizeof(struct clients*)) ;

	/* Initialize logger */
	openlog("iprohc_server", LOG_PID | LOG_PERROR , LOG_DAEMON) ;

	/* Signal for stats and log */
	signal(SIGINT,  quit) ;
	signal(SIGTERM, quit) ;
	signal(SIGUSR1, dump_stats) ;
	signal(SIGUSR2, switch_log_max) ;

	/*
	 * Parsing options
	 */
    struct option options[] = {
        { "port",   required_argument, NULL, 'p' },
        { "pidfile",   required_argument, NULL, 'f' },
        { "debug",   no_argument,      NULL, 'd' },
        { "help",   no_argument,       NULL, 'h' },
        {NULL, 0, 0, 0}
                              } ;
    int option_index = 0;
    do {
        c = getopt_long(argc, argv, "p:hdf:", options, &option_index) ;
        switch (c) {
            case 'd' :
				log_max_priority = LOG_DEBUG ;
                trace(LOG_DEBUG, "Debugging enabled") ;
               break ;
            case 'f' :
                strncpy(pidfile_path, optarg, 1024) ;
                trace(LOG_DEBUG, "Pid file : %s", pidfile_path) ;
               break ;
            case 'p' :
                port = atoi(optarg) ;
                trace(LOG_DEBUG, "Remote port : %d", port) ;
                break ;
            case 'h' :
                usage(argv[0]) ;
                break;
        }
    } while (c != -1) ;	

    if (strcmp(pidfile_path, "") == 0) {
    	trace(LOG_WARNING, "No pidfile specified") ;
    } else {
    	pid = fopen(pidfile_path, "w") ;
    	if (pid < 0) {
    		trace(LOG_ERR, "Unable to write open file : %s", strerror(errno)) ;
    	}
    	fprintf(pid, "%d\n", getpid()) ;
    	fclose(pid) ;
    }

	/* 
	 * Create TCP socket 
	 */
	serv_socket = socket(AF_INET, SOCK_STREAM, 0) ;
	int on = 1; 
	setsockopt(serv_socket,SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)); 

	struct	sockaddr_in servaddr ;
	servaddr.sin_family	  = AF_INET;
	servaddr.sin_addr.s_addr = htonl(address);
	servaddr.sin_port		= htons(port);

	if (bind(serv_socket, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		trace(LOG_ERR, "Bind failed : %s", strerror(errno)) ;
		goto error ;
	}
	
	if (listen(serv_socket, 10) < 0) {
		trace(LOG_ERR, "Listen failed : %s", strerror(errno)) ;
		goto error;
	}

	max = serv_socket ;

	/* params */
	struct tunnel_params params ;
    params.local_address       = inet_addr("192.168.99.1") ; /* Sets the IP address of the server */
    params.packing             = 4 ;
    params.max_cid             = 14 ;
    params.is_unidirectional   = 1 ;
    params.wlsb_window_width   = 23 ;
    params.refresh             = 9 ;
    params.keepalive_timeout   = 60 ;
    params.rohc_compat_version = 1 ;

	/* TUN create */
	tun = create_tun("tun_ipip", &tun_itf_id) ;
	if (tun < 0) {
		trace(LOG_ERR, "Unable to create TUN device") ;
		goto error ;
	}

	if (set_ip4(tun_itf_id, params.local_address, 24) < 0) {
		trace(LOG_ERR, "Unable to set IPv4 on tun device") ;
		goto error ;
	}

	/* TUN routing thread */
	route_args_tun.fd = tun ;
	route_args_tun.clients = clients ;
	route_args_tun.type = TUN ;
	pthread_create(&route_thread, NULL, route, (void*)&route_args_tun) ;

	/* RAW create */
	raw = create_raw() ;
	if (raw < -1) {
		trace(LOG_ERR, "Unable to create RAW socket") ;
		goto error ;
	}

	/* RAW routing thread */
	route_args_raw.fd = raw ;
	route_args_raw.clients = clients ;
	route_args_raw.type = RAW ;
	pthread_create(&route_thread, NULL, route, (void*)&route_args_raw) ;

	struct timespec timeout ;

	struct timeval now ;

    /* mask signals during interface polling */
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGUSR1);
    sigaddset(&sigmask, SIGUSR2);

	/* Start listening and looping on TCP socket */
	int alive = 1 ;
	while (alive) {
		gettimeofday(&now, NULL) ;
		FD_ZERO(&rdfs); 
		FD_SET(serv_socket, &rdfs);		
		max = serv_socket ;

		/* Add client to select readfds */
		for (j=0; j<MAX_CLIENTS; j++) {
			if (clients[j] != NULL && clients[j]->tunnel.alive >= 0) {
				FD_SET(clients[j]->tcp_socket, &rdfs) ;
				max = (clients[j]->tcp_socket > max)? clients[j]->tcp_socket : max ;
			}
		}

		/* Reset timeout */
		timeout.tv_sec = 1;
		timeout.tv_nsec = 0;

		if(pselect(max + 1, &rdfs, NULL, NULL, &timeout, &sigmask) == -1) {
			trace(LOG_ERR, "select failed : %s", strerror(errno));
			break ;
		}

		/* Read on serv_socket : new client */
		if (FD_ISSET(serv_socket, &rdfs)) {
			ret = new_client(serv_socket, tun, clients, MAX_CLIENTS, params) ;
			if (ret < 0) {
				trace(LOG_ERR, "new_client returned %d\n", ret) ;
				/* TODO : HANDLE THAT */
			}
		}

		/* Test read on each client socket */
		for (j=0; j<MAX_CLIENTS; j++) {
			if (clients[j] == NULL) {
				continue ;
			}

			if (clients[j]->tunnel.alive == 1 && 
				(clients[j]->last_keepalive.tv_sec == -1 || 
				 clients[j]->last_keepalive.tv_sec + ceil(clients[j]->tunnel.params.keepalive_timeout/3) < now.tv_sec)) {
				/* send keepalive */
				keepalive(clients[j]->tcp_socket) ;
				gettimeofday(&(clients[j]->last_keepalive), NULL) ;
			} else if (clients[j]->tunnel.alive == -1) {
				/* free dead client */
				trace(LOG_DEBUG, "Freeing %p", clients[j]) ;
				dump_stats_client(clients[j]) ;
				close(clients[j]->tcp_socket) ;
				free(clients[j]) ;
				clients[j] = NULL ;
			} else if (FD_ISSET(clients[j]->tcp_socket, &rdfs)) {
				/* handle request */
				ret = handle_client_request(clients[j], params) ;
				if (ret < 0) {
					if (clients[j]->tunnel.alive > 0) {
						trace(LOG_WARNING, "[%s] Client disconnected", inet_ntoa(clients[j]->tunnel.dest_address)) ;
						clients[j]->tunnel.alive = 0 ;
					}
				}
			}
		}
	}

	if (strcmp(pidfile_path, "") != 0) {
		unlink(pidfile_path) ;
	}
	return 0 ;

error :
	if (strcmp(pidfile_path, "") != 0) {
		unlink(pidfile_path) ;
	}
	exit(1) ;
}
