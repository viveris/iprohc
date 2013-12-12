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

/* server.c -- Implements server side of the ROHC IP-IP tunnel
*/

#include "tun_helpers.h"
#include "client.h"
#include "tls.h"
#include "server_config.h"
#include "rohc_tunnel.h"
#include "log.h"
#include "utils.h"

#include "config.h"

#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <getopt.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>

#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>


/** Print in logs a trace related to the given client */
#define client_trace(client, prio, format, ...) \
	do \
	{ \
		trace((prio), "[main] [client %s] " format, \
		      (client)->session.dst_addr_str, ##__VA_ARGS__); \
	} \
	while(0)


int log_max_priority = LOG_INFO;
bool iprohc_log_stderr = true;


/*
 * Route function that will be threaded twice to route
 * from tun to fake_tun and from raw to fake_raw
*/
enum type_route { TUN, RAW };

struct route_args
{
	int fd;
	int p2c[2];
	struct iprohc_server_session *clients;
	size_t clients_max_nr;   /**< The maximum number of simultaneous clients */
	enum type_route type;
};

static void * route(void *arg);

static bool iprohc_server_handle_new_client(const int serv_sock,
                                            struct iprohc_server_session *const clients,
                                            size_t *const clients_nr,
                                            const size_t clients_max_nr,
                                            const int raw,
                                            const int tun,
                                            const size_t tun_itf_mtu,
                                            const size_t basedev_mtu,
                                            const struct server_opts server_opts)
	__attribute__((warn_unused_result, nonnull(2, 3)));
	
static void dump_stats_client(struct iprohc_server_session *const client)
	__attribute__((nonnull(1)));


/**
 * @brief Print the usage of the IP/ROHC server
 */
static void usage(void)
{
	printf("IP/ROHC server: establish tunnels requested by IP/ROHC clients\n"
	       "\n"
	       "Usage: iprohc_server -b itfname [opts]\n"
	       "   or: iprohc_server -h|--help\n"
	       "   or: iprohc_server -v|--version\n"
	       "\n"
	       "Options:\n"
	       "Mandatory options:\n"
	       "  -b, --basedev ITF   Name of the underlying interface\n"
	       "\n"
	       "Other options:\n"
	       "  -c, --conf PATH     Path to configuration file\n"
	       "                      (default: /etc/iprohc_server.conf)\n"
	       "      --nofdlimit     Do not set the file descriptor limit\n"
	       "                      (for use with Valgrind)\n"
	       "  -d, --debug         Enable debuging\n"
	       "  -h, --help          Print this help message\n"
	       "  -v, --version       Print the software version\n"
	       "\n"
	       "Examples:\n"
	       "\n"
	       "Start the IP/ROHC server with default configuration file, compute\n"
	       "tunnel MTU based on network interface eth0:\n"
	       "  iprohc_server -b eth0\n"
	       "\n"
	       "Start the IP/ROHC server with the given configuration file, compute\n"
	       "tunnel MTU based on network interface wlan:\n"
	       "  iprohc_server -b wlan -c /etc/iprohc/server.cnf\n"
	       "\n"
	       "Print software version:\n"
	       "  iprohc_server --version\n"
	       "\n"
	       "Print usage help:\n"
	       "  iprohc_server --help\n"
	       "\n"
	       "Report bugs to <%s>.\n",
	       PACKAGE_BUGREPORT);
}


/**
 * @brief The main entry point of the IP/ROHC server
 *
 * @param argc  The number of arguments given on command line
 * @param argv  The arguments given on command line
 * @return      0 in case of success,
 *              2 if configuration file is invalid,
 *              1 in all other error cases.
 */
int main(int argc, char *argv[])
{
	int exit_status = 1;

	struct iprohc_server_session *clients = NULL;
	size_t clients_nr = 0;

	bool nofdlimit = false;

	size_t client_id;
	int serv_socket;

	int tun, raw;
	int tun_itf_id;
	size_t tun_itf_mtu;
	size_t basedev_mtu;

	struct route_args route_args_tun;
	struct route_args route_args_raw;
	pthread_t tun_route_thread;
	pthread_t raw_route_thread;

	int j;
	int ret;

	int signal_fd;
	sigset_t mask;
	bool is_server_alive;
	struct timeval now;

	struct epoll_event poll_signal;
	struct epoll_event poll_serv;
	const size_t max_events_nr = 1;
	struct epoll_event events[max_events_nr];
	int pollfd;

	gnutls_dh_params_t dh_params;

	struct server_opts server_opts;
	FILE*pid;

	bool is_ok;
	int c;
	char conf_file[1024];
	strcpy(conf_file, "/etc/iprohc_server.conf");

	/* Initialize logger */
	openlog("iprohc_server", LOG_PID, LOG_DAEMON);


	/*
	 * Parsing options
	 */

	/* Default values */
	server_opts.clients_max_nr = 50;
	server_opts.port = 3126;
	server_opts.pkcs12_f[0] = '\0';
	server_opts.pidfile_path[0]  = '\0';
	memset(server_opts.basedev, 0, IFNAMSIZ);
	server_opts.local_address = inet_addr("192.168.99.1");
	server_opts.netmask = 24;

	server_opts.params.packing             = 5;
	server_opts.params.max_cid             = 14;
	server_opts.params.is_unidirectional   = 1;
	server_opts.params.wlsb_window_width   = 23;
	server_opts.params.refresh             = 9;
	server_opts.params.keepalive_timeout   = 60;
	server_opts.params.rohc_compat_version = 1;

	struct option options[] = {
		{ "conf",      required_argument, NULL, 'c' },
		{ "basedev",   required_argument, NULL, 'b' },
		{ "nofdlimit", no_argument,       NULL, 'n' },
		{ "debug",     no_argument,       NULL, 'd' },
		{ "help",      no_argument,       NULL, 'h' },
		{ "version",   no_argument,       NULL, 'v' },
		{NULL, 0, 0, 0}
	};
	int option_index = 0;
	do
	{
		c = getopt_long(argc, argv, "c:b:nhvd", options, &option_index);
		switch(c)
		{
			case 'c':
				trace(LOG_DEBUG, "[main] Using file : %s", optarg);
				strncpy(conf_file, optarg, 1024);
				conf_file[1023] = '\0';
				break;
			case 'b':
				trace(LOG_DEBUG, "[main] underlying interface: %s", optarg);
				if(strlen(optarg) >= IFNAMSIZ)
				{
					trace(LOG_ERR, "[main] underlying interface name too long");
					goto error;
				}
				if(if_nametoindex(optarg) <= 0)
				{
					trace(LOG_ERR, "[main] underlying interface '%s' does not exist",
					      optarg);
					goto error;
				}
				strncpy(server_opts.basedev, optarg, IFNAMSIZ);
				break;
			case 'n':
				trace(LOG_NOTICE, "[main] option --nofdlimit specified");
				nofdlimit = true;
				break;
			case 'd':
				log_max_priority = LOG_DEBUG;
				trace(LOG_DEBUG, "[main] debug mode enabled");
				break;
			case 'h':
				usage();
				goto error;
			case 'v':
				printf("IP/ROHC server, version %s%s", PACKAGE_VERSION,
				       PACKAGE_REVNO);
				goto error;
		}
	}
	while(c != -1);

	/* load configuration from file, and check its coherency */
	if(!iprohc_server_load_config(conf_file, &server_opts))
	{
		trace(LOG_ERR, "[main] failed to load configuration file '%s'", conf_file);
		exit_status = 2;
		goto error;
	}

	/* create PID file */
	if(strcmp(server_opts.pidfile_path, "") == 0)
	{
		trace(LOG_WARNING, "[main] No pidfile specified");
	}
	else
	{
		pid = fopen(server_opts.pidfile_path, "w");
		if(pid == NULL)
		{
			trace(LOG_ERR, "[main] failed to open pidfile '%s': %s (%d)",
			      server_opts.pidfile_path, strerror(errno), errno);
			goto error;
		}
		fprintf(pid, "%d\n", getpid());
		fclose(pid);
	}


	/*
	 * Handle signals for stats and log
	 */

	signal(SIGHUP, SIG_IGN); /* used to stop client threads */
	signal(SIGPIPE, SIG_IGN); /* don't stop if TCP connection was unexpectedly closed */

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGPIPE); /* don't stop if TCP connection was unexpectedly closed */
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);

	/* block signals to handle them through signal fd */
	ret = sigprocmask(SIG_BLOCK, &mask, NULL);
	if(ret != 0)
	{
		trace(LOG_ERR, "[main] failed to block UNIX signals: %s (%d)",
		      strerror(errno), errno);
		goto remove_pidfile;
	}

	/* create signal fd */
	signal_fd = signalfd(-1, &mask, 0);
	if(signal_fd < 0)
	{
		trace(LOG_ERR, "[main] failed to create signal fd: %s (%d)",
		      strerror(errno), errno);
		goto remove_pidfile;
	}


	/*
	 * Set system limits
	 */

	if(!nofdlimit)
	{
		const size_t fds_nr_base = 20U;
		const size_t fds_nr_per_client = 9U;
		const size_t fds_max_nr =
			fds_nr_base + server_opts.clients_max_nr * fds_nr_per_client;
		const struct rlimit fd_limits = {
			.rlim_cur = fds_max_nr,
			.rlim_max = fds_max_nr + 1,
		};

		ret = setrlimit(RLIMIT_NOFILE, &fd_limits);
		if(ret != 0)
		{
			trace(LOG_ERR, "[main] failed to set system limits: failed to limit "
			      "the number of file descriptors to %zu: %s (%d)", fds_max_nr,
			      strerror(errno), errno);
			goto close_signal_fd;
		}
		trace(LOG_INFO, "[main] set system limit for the number of file "
		      "descriptors to %zu", fds_max_nr);
	}


	/*
	 * Initialize contexts for clients
	 */

	clients = calloc(server_opts.clients_max_nr,
	                 sizeof(struct iprohc_server_session));
	if(clients == NULL)
	{
		trace(LOG_ERR, "[main] failed to allocate memory for the contexts of %zu "
		      "clients", server_opts.clients_max_nr);
		goto close_signal_fd;
	}
	clients_nr = 0;
	for(size_t i = 0; i < server_opts.clients_max_nr; i++)
	{
		memcpy(&(clients[i].session.tunnel.params), &(server_opts.params),
		       sizeof(struct tunnel_params));
		AO_store_release_write(&(clients[i].is_init), 0);
	}


	/*
	 * GnuTLS stuff
	 */

	trace(LOG_INFO, "[main] load server certificate from file '%s'",
			server_opts.pkcs12_f);
	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&(server_opts.tls_cred));
	gnutls_priority_init(&(server_opts.priority_cache), "NORMAL", NULL);
	if(!load_p12(server_opts.tls_cred, server_opts.pkcs12_f, ""))
	{
		if(!load_p12(server_opts.tls_cred, server_opts.pkcs12_f, NULL))
		{
			trace(LOG_ERR, "[main] failed to load server certificate from file '%s'",
					server_opts.pkcs12_f);
			goto deinit_tls;
		}
	}

	trace(LOG_INFO, "[main] generate Diffie–Hellman parameters (it takes a few seconds)");
	if(!generate_dh_params(&dh_params))
	{
		trace(LOG_ERR, "[main] failed to generate Diffie-Hellman parameters");
		goto deinit_tls;
	}
	gnutls_certificate_set_dh_params(server_opts.tls_cred, dh_params);


	/*
	 * Create TCP socket
	 */
	trace(LOG_INFO, "[main] listen on TCP 0.0.0.0:%d", server_opts.port);
	serv_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(serv_socket < 0)
	{
		trace(LOG_ERR, "[main] failed to create TCP socket: %s (%d)",
				strerror(errno), errno);
		goto free_dh;
	}
	int on = 1;
	ret = setsockopt(serv_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if(ret != 0)
	{
		trace(LOG_ERR, "[main] failed to allow the TCP socket to re-use address: %s (%d)",
				strerror(errno), errno);
		goto close_tcp;
	}

	struct   sockaddr_in servaddr;
	servaddr.sin_family    = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port    = htons(server_opts.port);

	ret = bind(serv_socket, (struct sockaddr*)&servaddr, sizeof(servaddr));
	if(ret != 0)
	{
		trace(LOG_ERR, "[main] failed to bind on TCP/%d: %s (%d)", server_opts.port,
				strerror(errno), errno);
		goto close_tcp;
	}

	ret = listen(serv_socket, 10);
	if(ret != 0)
	{
		trace(LOG_ERR, "[main] failed to put TCP/%d socket in listen mode: %s (%d)",
				server_opts.port, strerror(errno), errno);
		goto close_tcp;
	}

	/* TUN create */
	trace(LOG_INFO, "[main] create TUN interface");
	tun = create_tun("tun_ipip", server_opts.basedev,
	                 &tun_itf_id, &basedev_mtu, &tun_itf_mtu);
	if(tun < 0)
	{
		trace(LOG_ERR, "[main] failed to create TUN device");
		goto close_tcp;
	}

	is_ok = set_ip4(tun_itf_id, server_opts.local_address, 24);
	if(!is_ok)
	{
		trace(LOG_ERR, "[main] failed to set IPv4 address on TUN interface");
		goto delete_tun;
	}

	/* TUN routing thread */
	trace(LOG_INFO, "[main] start TUN routing thread");
	route_args_tun.fd = tun;
	ret = pipe(route_args_tun.p2c);
	if(ret != 0)
	{
		trace(LOG_ERR, "[main] failed to create communication pipe for TUN "
		      "routing thread: %s (%d)", strerror(errno), errno);
		goto delete_tun;
	}
	route_args_tun.clients = clients;
	route_args_tun.clients_max_nr = server_opts.clients_max_nr;
	route_args_tun.type = TUN;
	ret = pthread_create(&tun_route_thread, NULL, route, (void*)&route_args_tun);
	if(ret != 0)
	{
		trace(LOG_ERR, "[main] failed to create the TUN routing thread: %s (%d)",
				strerror(ret), ret);
		goto close_tun_pipe;
	}

	/* RAW create */
	trace(LOG_INFO, "[main] create RAW socket");
	raw = create_raw();
	if(raw < 0)
	{
		trace(LOG_ERR, "[main] failed to create RAW socket");
		goto stop_tun_thread;
	}

	/* RAW routing thread */
	trace(LOG_INFO, "[main] start RAW routing thread");
	route_args_raw.fd = raw;
	ret = pipe(route_args_raw.p2c);
	if(ret != 0)
	{
		trace(LOG_ERR, "[main] failed to create communication pipe for RAW "
		      "routing thread: %s (%d)", strerror(errno), errno);
		goto delete_raw;
	}
	route_args_raw.clients = clients;
	route_args_raw.clients_max_nr = server_opts.clients_max_nr;
	route_args_raw.type = RAW;
	ret = pthread_create(&raw_route_thread, NULL, route, (void*)&route_args_raw);
	if(ret != 0)
	{
		trace(LOG_ERR, "[main] failed to create the RAW routing thread: %s (%d)",
				strerror(ret), ret);
		goto close_raw_pipe;
	}

	/* stop writing logs on stderr */
	iprohc_log_stderr = false;

	/* we want to monitor some fds */
	pollfd = epoll_create(1);
	if(pollfd < 0)
	{
		trace(LOG_ERR, "[main] failed to create epoll context: %s (%d)",
		      strerror(errno), errno);
		goto stop_raw_thread;
	}

	/* will monitor the signal fd */
	poll_signal.events = EPOLLIN;
	memset(&poll_signal.data, 0, sizeof(poll_signal.data));
	poll_signal.data.fd = signal_fd;
	ret = epoll_ctl(pollfd, EPOLL_CTL_ADD, signal_fd, &poll_signal);
	if(ret != 0)
	{
		trace(LOG_ERR, "[main] failed to add signal to epoll context: %s (%d)",
		      strerror(errno), errno);
		goto close_pollfd;
	}

	/* will monitor the server socket */
	poll_serv.events = EPOLLIN;
	memset(&poll_serv.data, 0, sizeof(poll_serv.data));
	poll_serv.data.fd = serv_socket;
	ret = epoll_ctl(pollfd, EPOLL_CTL_ADD, serv_socket, &poll_serv);
	if(ret != 0)
	{
		trace(LOG_ERR, "[main] failed to add server socket to epoll context: "
		      "%s (%d)", strerror(errno), errno);
		goto close_pollfd;
	}

	/* Start listening and looping on TCP socket */
	trace(LOG_INFO, "[main] server is now ready to accept requests from clients");
	is_server_alive = true;
	while(is_server_alive)
	{
		const int timeout = 10 * 1000; /* in milliseconds */

		gettimeofday(&now, NULL);

		/* wait for events */
		ret = epoll_wait(pollfd, events, max_events_nr, timeout);
		if(ret < 0)
		{
			trace(LOG_ERR, "[main] epoll_wait failed: %s (%d)", strerror(errno), errno);
			continue;
		}
		else if(ret == 0)
		{
			trace(LOG_DEBUG, "[main] epoll_wait: timeout expired without any event");
			continue;
		}
		trace(LOG_DEBUG, "[main] epoll_wait: %d event(s)", ret);

		/* UNIX signal received? */
		if(events[0].data.fd == signal_fd)
		{
			struct signalfd_siginfo signal_infos;

			ret = read(signal_fd, &signal_infos, sizeof(struct signalfd_siginfo));
			if(ret < 0)
			{
				trace(LOG_ERR, "[main] failed to retrieve information about the received "
				      "UNIX signal: %s (%d)", strerror(errno), errno);
				continue;
			}
			else if(ret != sizeof(struct signalfd_siginfo))
			{
				trace(LOG_ERR, "[main] failed to retrieve information about the received "
				      "UNIX signal: only %d bytes expected while %zu bytes received",
				      ret, sizeof(struct signalfd_siginfo));
				continue;
			}

			switch(signal_infos.ssi_signo)
			{
				case SIGINT:
				case SIGTERM:
				case SIGQUIT:
				{
					if(signal_infos.ssi_pid > 0)
					{
						/* killed by known process */
						trace(LOG_NOTICE, "[main] process with PID %d run by user with UID "
						      "%d asked the IP/ROHC server to shutdown",
						      signal_infos.ssi_pid, signal_infos.ssi_uid);
					}
					else
					{
						/* killed by unknown process */
						trace(LOG_NOTICE, "[main] user with UID %d asked the IP/ROHC server "
						      "to shutdown", signal_infos.ssi_uid);
					}
					is_server_alive = false;
					continue;
				}
				case SIGUSR1:
				{
					/* dump stats for all clients */
					trace(LOG_INFO, "[main] dump stats for all clients");
					for(j = 0; j < server_opts.clients_max_nr; j++)
					{
						if(AO_load_acquire_read(&(clients[j].is_init)))
						{
							dump_stats_client(&(clients[j]));
						}
					}
					trace(LOG_INFO, "[main] end of stats dump");
					break;
				}
				case SIGUSR2:
					/* toggle between debug and non-debug modes */
					if(log_max_priority == LOG_DEBUG)
					{
						log_max_priority = LOG_INFO;
						trace(LOG_INFO, "[main] debug mode disabled");
					}
					else
					{
						log_max_priority = LOG_DEBUG;
						trace(LOG_DEBUG, "[main] debug mode enabled");
					}
					break;
				default:
				{
					trace(LOG_NOTICE, "[main] ignore unexpected signal %d",
					      signal_infos.ssi_signo);
					break;
				}
			}
		}

		/* Read on serv_socket : new client */
		if(events[0].data.fd == serv_socket)
		{
			trace(LOG_INFO, "[main] new connection from client");
			if(!iprohc_server_handle_new_client(serv_socket, clients, &clients_nr,
			                                    server_opts.clients_max_nr,
			                                    raw, tun, tun_itf_mtu, basedev_mtu,
			                                    server_opts))
			{
				trace(LOG_ERR, "[main] failed to handle new client session");
			}
		}

		/* cleanup deconnected clients */
		for(j = 0; j < server_opts.clients_max_nr; j++)
		{
			/* skip uninitialized clients */
			if(!AO_load_acquire_read(&(clients[j].is_init)))
			{
				continue;
			}

			/* skip clients that are still running */
			if(AO_load_acquire_read(&(clients[j].session.is_thread_running)))
			{
				continue;
			}

			/* client is not running, we can check its status */
			if(clients[j].session.status == IPROHC_SESSION_PENDING_DELETE)
			{
				/* stop client session */
				trace(LOG_INFO, "[main] stop session of client #%d", j);
				if(!iprohc_session_stop(&(clients[j].session)))
				{
					trace(LOG_ERR, "[main] failed to stop session of client #%d", j);
				}

				/* delete client */
				trace(LOG_INFO, "[main] remove context of client #%d", j);
				del_client(&(clients[j]));
					
				assert(clients_nr > 0);
				assert(clients_nr <= server_opts.clients_max_nr);
				clients_nr--;
				trace(LOG_INFO, "[main] only %zu/%zu clients remaining", clients_nr,
				      server_opts.clients_max_nr);
				assert(clients_nr >= 0);
				assert(clients_nr < server_opts.clients_max_nr);
			}
		}
	}
	trace(LOG_INFO, "[main] stopping server...");

	/* release all clients */
	trace(LOG_INFO, "[main] release resources of connected clients...");
	for(client_id = 0; client_id < server_opts.clients_max_nr; client_id++)
	{
		if(AO_load_acquire_read(&(clients[client_id].is_init)))
		{
			/* stop client session */
			trace(LOG_INFO, "[main] stop session of client #%zu", client_id);
			if(!iprohc_session_stop(&(clients[client_id].session)))
			{
				trace(LOG_ERR, "[main] failed to stop session of client #%zu",
				      client_id);
			}

			trace(LOG_INFO, "[main] remove context of client #%zu", client_id);
			del_client(&(clients[client_id]));
		}
	}

	/* everything went fine */
	exit_status = 0;

close_pollfd:
	close(pollfd);
stop_raw_thread:
	trace(LOG_INFO, "[main] stop RAW routing thread...");
	close(route_args_raw.p2c[1]);
	route_args_raw.p2c[1] = -1;
	pthread_join(raw_route_thread, NULL);
close_raw_pipe:
	if(route_args_raw.p2c[1] >= 0)
	{
		close(route_args_raw.p2c[1]);
	}
	close(route_args_raw.p2c[0]);
delete_raw:
	trace(LOG_INFO, "[main] close RAW socket");
	close(raw);
stop_tun_thread:
	trace(LOG_INFO, "[main] stop TUN routing thread...");
	close(route_args_tun.p2c[1]);
	route_args_tun.p2c[1] = -1;
	pthread_join(tun_route_thread, NULL);
close_tun_pipe:
	if(route_args_tun.p2c[1] >= 0)
	{
		close(route_args_tun.p2c[1]);
	}
	close(route_args_tun.p2c[0]);
delete_tun:
	trace(LOG_INFO, "[main] close TUN interface");
	close(tun);
close_tcp:
	trace(LOG_INFO, "[main] close TCP server socket");
	close(serv_socket);
free_dh:
	gnutls_dh_params_deinit(dh_params);
deinit_tls:
	trace(LOG_INFO, "[main] release TLS resources");
	gnutls_certificate_free_credentials(server_opts.tls_cred);
	gnutls_priority_deinit(server_opts.priority_cache);
	gnutls_global_deinit();
/*free_client_contexts:*/
	free(clients);
close_signal_fd:
	close(signal_fd);
remove_pidfile:
	if(strcmp(server_opts.pidfile_path, "") != 0)
	{
		trace(LOG_INFO, "[main] remove pidfile '%s'", server_opts.pidfile_path);
		unlink(server_opts.pidfile_path);
	}
error:
	if(exit_status == 0)
	{
		trace(LOG_INFO, "[main] server stops with exit code %d", exit_status);
	}
	else
	{
		trace(LOG_NOTICE, "[main] server stops with exit code %d", exit_status);
	}
	trace(LOG_INFO, "[main] close syslog session");
	closelog();
	return exit_status;
}


/**
 * @brief Accept or reject a new client session
 *
 * @param serv_sock           The server socket in listen state
 * @param clients             The contexts for all clients
 * @param[in,out] clients_nr  The number of clients currently connected
 * @param clients_max_nr      The maximum number of clients accepted
 * @param raw                 The RAW socket
 * @param tun                 The file descriptor of the TUN interface
 * @param tun_itf_mtu         The MTU of the TUN interface
 * @param basedev_mtu         The MTU of the underlying interface
 * @param server_opts         The server configuration
 * @return                    true if client session was accepted or rejected,
 *                            false if a problem occurred during acception/rejection
 */
static bool iprohc_server_handle_new_client(const int serv_sock,
                                            struct iprohc_server_session *const clients,
                                            size_t *const clients_nr,
                                            const size_t clients_max_nr,
                                            const int raw,
                                            const int tun,
                                            const size_t tun_itf_mtu,
                                            const size_t basedev_mtu,
                                            const struct server_opts server_opts)
{
	struct sockaddr_in remote_addr;
	socklen_t remote_addr_len = sizeof(struct sockaddr_in);
	int conn;

	assert(serv_sock >= 0);
	assert(clients != NULL);
	assert(clients_nr != NULL);
	assert(clients_max_nr > 0);
	assert((*clients_nr) <= clients_max_nr);
	assert(raw >= 0);
	assert(tun >= 0);

	/* accept connection */
	conn = accept(serv_sock, (struct sockaddr *) &remote_addr, &remote_addr_len);
	if(conn < 0)
	{
		trace(LOG_ERR, "[main] failed to accept new connection on socket %d: %s (%d)",
				serv_sock, strerror(errno), errno);
		goto error;
	}

	/* enough resources for a new client? */
	if((*clients_nr) >= clients_max_nr)
	{
		/* not enough resource, kick the new client away */
		trace(LOG_ERR, "[main] no more clients accepted, maximum %zu reached",
		      clients_max_nr);

		/* reject connection */
		close(conn);
	}
	else
	{
		size_t client_id;
		int ret;

		/* find the first free context for the new client */
		for(client_id = 0; client_id < clients_max_nr &&
		    AO_load_acquire_read(&(clients[client_id].is_init)); client_id++)
		{
		}
		assert(client_id < clients_max_nr);
		trace(LOG_INFO, "[main] will store client %zu/%zu at index %zu",
		      (*clients_nr) + 1, clients_max_nr, client_id);

		ret = new_client(conn, remote_addr, raw, tun, tun_itf_mtu, basedev_mtu,
		                 &(clients[client_id]), client_id, server_opts);
		if(ret < 0)
		{
			trace(LOG_ERR, "[main] failed to init new client session (%d)\n", ret);
			close(conn);
			goto error;
		}
		
		/* start client thread */
		if(!iprohc_session_start(&(clients[client_id].session)))
		{
			trace(LOG_ERR, "[main] failed to start client thread");
			del_client(&(clients[client_id]));
			goto error;
		}

		/* one client more */
		assert((*clients_nr) < clients_max_nr);
		(*clients_nr)++;
	}

	return true;

error:
	return false;
}


/**
 * @brief Dump the statistics of the given client in logs
 *
 * @warning THIS FUNCTION IS NOT THREAD-SAFE
 *
 * @param client  The client session
 */
static void dump_stats_client(struct iprohc_server_session *const client)
{
	client_trace(client, LOG_INFO, "--------------------------------------------");
	switch(client->session.status)
	{
		case IPROHC_SESSION_CONNECTING:
			client_trace(client, LOG_INFO, "status: connecting");
			break;
		case IPROHC_SESSION_CONNECTED:
			client_trace(client, LOG_INFO, "status: connected");
			break;
		case IPROHC_SESSION_PENDING_DELETE:
			client_trace(client, LOG_INFO, "status: pending delete");
			break;
		default:
			client_trace(client, LOG_INFO, "status: unknown (%d)",
			             client->session.status);
			break;
	}
	if(client->session.status == IPROHC_SESSION_CONNECTED)
	{
		int i;

		client_trace(client, LOG_INFO, "packing: %d", client->session.tunnel.params.packing);
		client_trace(client, LOG_INFO, "stats:");
		client_trace(client, LOG_INFO, "  failed decompression:          %d",
		             client->session.tunnel.stats.decomp_failed);
		client_trace(client, LOG_INFO, "  total  decompression:          %d",
		             client->session.tunnel.stats.decomp_total);
		client_trace(client, LOG_INFO, "  failed compression:            %d",
		             client->session.tunnel.stats.comp_failed);
		client_trace(client, LOG_INFO, "  total  compression:            %d",
		             client->session.tunnel.stats.comp_total);
		client_trace(client, LOG_INFO, "  failed depacketization:        %d",
		             client->session.tunnel.stats.unpack_failed);
		client_trace(client, LOG_INFO, "  total received packets on raw: %d",
		             client->session.tunnel.stats.total_received);
		client_trace(client, LOG_INFO, "  total compressed header size:  %d bytes",
		             client->session.tunnel.stats.head_comp_size);
		client_trace(client, LOG_INFO, "  total compressed packet size:  %d bytes",
		             client->session.tunnel.stats.total_comp_size);
		client_trace(client, LOG_INFO, "  total header size before comp: %d bytes",
		             client->session.tunnel.stats.head_uncomp_size);
		client_trace(client, LOG_INFO, "  total packet size before comp: %d bytes",
		             client->session.tunnel.stats.total_uncomp_size);
		client_trace(client, LOG_INFO, "stats packing:");
		for(i = 1; i < client->session.tunnel.stats.n_stats_packing; i++)
		{
			client_trace(client, LOG_INFO, "  %d packets: %d", i,
			             client->session.tunnel.stats.stats_packing[i]);
		}
	}
	client_trace(client, LOG_INFO, "--------------------------------------------");
}


/**
 * @brief Route RAW or TUN traffic to related clients
 *
 * Use client's IP address to route traffic to the related client socketpair.
 *
 * @param arg  The route context
 * @return     Always NULL
 */
static void * route(void *arg)
{
	/* Getting args */
	const struct route_args *const _arg = (struct route_args *) arg;
	int fd = _arg->fd;
	struct iprohc_server_session *clients = _arg->clients;
	size_t clients_max_nr = _arg->clients_max_nr;
	enum type_route type = _arg->type;

	bool is_route_thread_alive = true;
	size_t len;
	int ret;
	int i;

	struct epoll_event poll_pipe;
	struct epoll_event poll_sock;
	const size_t max_events_nr = 2;
	struct epoll_event events[max_events_nr];
	int pollfd;

	unsigned char buffer[TUNTAP_BUFSIZE];
	unsigned int buffer_len = TUNTAP_BUFSIZE;

	struct in_addr addr;

	uint32_t*src_ip;
	uint32_t*dest_ip;

	trace(LOG_INFO, "[route] Initializing routing thread");

	/* we want to monitor some fds */
	pollfd = epoll_create(1);
	if(pollfd < 0)
	{
		trace(LOG_ERR, "[route] failed to create epoll context: %s (%d)",
		      strerror(errno), errno);
		goto error;
	}

	/* will monitor the read side of the pipe */
	poll_pipe.events = EPOLLIN;
	memset(&poll_pipe.data, 0, sizeof(poll_pipe.data));
	poll_pipe.data.fd = _arg->p2c[0];
	ret = epoll_ctl(pollfd, EPOLL_CTL_ADD, _arg->p2c[0], &poll_pipe);
	if(ret != 0)
	{
		trace(LOG_ERR, "[route] failed to add pipe to epoll context: %s (%d)",
		      strerror(errno), errno);
		goto close_pollfd;
	}

	/* will monitor the read side of the pipe */
	poll_sock.events = EPOLLIN;
	memset(&poll_sock.data, 0, sizeof(poll_sock.data));
	poll_sock.data.fd = fd;
	ret = epoll_ctl(pollfd, EPOLL_CTL_ADD, fd, &poll_sock);
	if(ret != 0)
	{
		trace(LOG_ERR, "[route] failed to add socket to epoll context: %s (%d)",
		      strerror(errno), errno);
		goto close_pollfd;
	}

	while(is_route_thread_alive)
	{
		/* wait for events */
		ret = epoll_wait(pollfd, events, max_events_nr, -1);
		if(ret < 0)
		{
			trace(LOG_ERR, "epoll_wait failed: %s (%d)", strerror(errno), errno);
			goto close_pollfd;
		}
		else if(ret == 0)
		{
			continue;
		}

		/* stop thread if main thread closed the write side of the pipe */
		if(events[0].data.fd == _arg->p2c[0])
		{
			goto quit;
		}

		if(events[0].data.fd == fd)
		{
			ret = read(fd, buffer, buffer_len);
			if(ret < 0)
			{
				trace(LOG_ERR, "[route] read failed: %s (%d)", strerror(errno),
				      errno);
				goto close_pollfd;
			}
			else if(ret != 0)
			{
				trace(LOG_ERR, "[route] nothing read on socket");
				goto close_pollfd;
			}
			len = ret;
			trace(LOG_DEBUG, "[route] read %zu bytes", len);

			/* Get packet destination IP if tun or source IP if raw */
			if(type == TUN)
			{
				dest_ip = (uint32_t*) &buffer[20];
				addr.s_addr = *dest_ip;
				trace(LOG_DEBUG, "[route] packet destination = %s", inet_ntoa(addr));
			}
			else
			{
				src_ip = (uint32_t*) &buffer[12];
				addr.s_addr = *src_ip;
				trace(LOG_DEBUG, "[route] packet source = %s", inet_ntoa(addr));
			}

			for(i = 0; i < clients_max_nr; i++)
			{
				/* Find associated client */
				if(!AO_load_acquire_read(&(clients[i].is_init)))
				{
					continue;
				}

				/* Send to fake raw or tun device */
				if(type == TUN)
				{
					if(addr.s_addr == clients[i].session.local_address.s_addr)
					{
						ret = write(clients[i].fake_tun[1], buffer, len);
						if(ret < 0)
						{
							trace(LOG_WARNING, "[route] failed to send %zu-byte packet "
							      "to TUN interface: %s (%d)", len, strerror(errno), errno);
						}
						else if(ret != len)
						{
							trace(LOG_WARNING, "[route] partial write: only %d bytes of "
							      "the %zu-byte packet were sent to the TUN interface",
							      ret, len);
						}
						break;
					}
				}
				else
				{
					if(addr.s_addr == clients[i].session.dst_addr.s_addr)
					{
						ret = write(clients[i].fake_raw[1], buffer, len);
						if(ret < 0)
						{
							trace(LOG_WARNING, "[route] failed to send %zu-byte packet "
							      "to the underlying interface: %s (%d)", len,
							      strerror(errno), errno);
						}
						else if(ret != len)
						{
							trace(LOG_WARNING, "[route] partial write: only %d bytes of "
							      "the %zu-byte packet were sent to the underlying "
							      "interface", ret, len);
						}
						break;
					}
				}
			}
		}
	}

quit:
	trace(LOG_INFO, "[route] end of thread");
close_pollfd:
	close(pollfd);
error:
	return NULL;
}

