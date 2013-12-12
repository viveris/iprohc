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

/* rohc_tunnel.c -- Functions handling a tunnel, client or server-side
*/

#include "session.h"
#include "ip_chksum.h"
#include "log.h"
#include "utils.h"

#include "config.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_tun.h>


/*
 * Macros & definitions:
 */

/// The maximal size of a ROHC packet
#define MAX_ROHC_SIZE   (5 * 1024)

#define MAX_TRACE_SIZE 2048


/** Print in logs a trace related to the given tunnel */
#define tunnel_trace(tunnel, prio, format, ...) \
	do \
	{ \
		if((tunnel)->dst_addr_str[0] == '\0') \
		{ \
			trace((prio), "[client %s] " format, \
			      (tunnel)->dst_addr_str, ##__VA_ARGS__); \
		} \
		else \
		{ \
			trace((prio), format, ##__VA_ARGS__); \
		} \
	} \
	while(0)



/* Prototypes for local functions */

void dump_packet(char *descr, unsigned char *packet, unsigned int length);
static void print_rohc_traces(rohc_trace_level_t level,
                              rohc_trace_entity_t entity,
                              int profile,
                              const char *format, ...)
__attribute__((format (printf, 4, 5)));
bool callback_rtp_detect(const unsigned char *const ip,
                         const unsigned char *const udp,
                         const unsigned char *const payload,
                         const unsigned int payload_size,
                         void *const rtp_private);
int send_puree(int to,
               struct in_addr raddr,
               const size_t mtu,
               unsigned char *compressed_packet,
               size_t *total_size,
               size_t *act_comp,
               struct statitics *stats);
int raw2tun(struct rohc_decomp *decomp,
            in_addr_t dst_addr,
            int from,
            int to,
				const size_t mtu,
            struct statitics *stats);
int tun2raw(struct rohc_comp *comp,
            int from,
            int to,
            struct in_addr raddr,
            const size_t mtu,
            unsigned char *const packing_frame,
            const size_t packing_max_len,
            size_t *const packing_cur_len,
            const size_t packing_max_pkts,
            size_t *const packing_cur_pkts,
            struct statitics *stats);

static void gnutls_transport_set_ptr_nowarn(gnutls_session_t session, int ptr);


/*
 * Main functions
 */


/**
 * @brief Initialize the given tunnel context
 *
 * @param tunnel        The tunnel context to initialize
 * @param params        The configuration parameters of the tunnel
 * @param local_addr    The local address for tunnel traffic
 * @param raw_socket    The RAW socket to use to send packets to remote endpoint
 * @param tun_fd        The file descriptor of the local TUN interface
 * @param base_dev_mtu  The MTU of the base device used to send packets to the
 *                      remote endpoint
 * @param tun_dev_mtu   The MTU of the local TUN interface
 * @return              true if tunnel was successfully initialized,
 *                      false if a problem occurred
 */
bool iprohc_tunnel_new(struct iprohc_tunnel *const tunnel,
                       const struct tunnel_params params,
                       const uint32_t local_addr,
                       const int raw_socket,
                       const int tun_fd,
                       const size_t base_dev_mtu,
                       const size_t tun_dev_mtu)
{
	rohc_mode_t rohc_mode;
	struct rohc_comp *asso_comp;
	bool is_ok;

	assert(tunnel != NULL);
	assert(raw_socket >= 0);
	assert(tun_fd >= 0);

	/* TUN interface */
	tunnel->tun_fd_in = tun_fd;
	tunnel->tun_fd_out = tun_fd;

	/* RAW socket */
	tunnel->raw_socket_in = raw_socket;
	tunnel->raw_socket_out = raw_socket;

	/* device MTU */
	tunnel->tun_itf_mtu = tun_dev_mtu;
	tunnel->basedev_mtu = base_dev_mtu;

	/* record tunnel parameters */
	memcpy(&tunnel->params, &params, sizeof(struct tunnel_params));

	/* record the local address */
	tunnel->params.local_address = local_addr;

	/* reset stats */
	memset(&tunnel->stats, 0, sizeof(struct statitics));
	tunnel->stats.n_stats_packing = tunnel->params.packing + 1;
	tunnel->stats.stats_packing = calloc(tunnel->stats.n_stats_packing, sizeof(int));
	if(tunnel->stats.stats_packing == NULL)
	{
		trace(LOG_ERR, "failed to allocate memory for packing stats");
		goto error;
	}

	/* create the compressor and activate profiles */
	tunnel->comp = rohc_comp_new(ROHC_SMALL_CID, tunnel->params.max_cid);
	if(tunnel->comp == NULL)
	{
		trace(LOG_ERR, "failed to create the ROHC compressor");
		goto free_packing_stats;
	}

	/* handle compressor traces */
	is_ok = rohc_comp_set_traces_cb(tunnel->comp, print_rohc_traces);
	if(!is_ok)
	{
		trace(LOG_ERR, "faield to set trace callback for compressor");
		goto destroy_comp;
	}

	/* enable all safe compression profiles */
	is_ok = rohc_comp_enable_profiles(tunnel->comp,
	                                  ROHC_PROFILE_UNCOMPRESSED,
	                                  ROHC_PROFILE_IP,
	                                  ROHC_PROFILE_UDP,
	                                  ROHC_PROFILE_RTP,
	                                  -1);
	if(!is_ok)
	{
		trace(LOG_ERR, "failed to enable profiles for compressor");
		goto destroy_comp;
	}

	/* set RTP callback for detecting RTP packets */
	is_ok = rohc_comp_set_rtp_detection_cb(tunnel->comp, callback_rtp_detect, NULL);
	if(!is_ok)
	{
		trace(LOG_ERR, "failed to set RTP detection callback");
		goto destroy_comp;
	}

	/* decompressor parameters that depend on operation mode */
	if(tunnel->params.is_unidirectional)
	{
		rohc_mode = ROHC_U_MODE;
		asso_comp = NULL;
	}
	else
	{
		rohc_mode = ROHC_O_MODE;
		asso_comp = tunnel->comp;
	}

	/* create the decompressor (associate it with the compressor) */
	tunnel->decomp = rohc_decomp_new(ROHC_SMALL_CID, tunnel->params.max_cid,
	                                 rohc_mode, asso_comp);
	if(tunnel->decomp == NULL)
	{
		trace(LOG_ERR, "failed to create the ROHC decompressor");
		goto destroy_comp;
	}

	/* handle compressor trace */
	is_ok = rohc_decomp_set_traces_cb(tunnel->decomp, print_rohc_traces);
	if(!is_ok)
	{
		trace(LOG_ERR, "failed to set trace callback for decompressor");
		goto destroy_decomp;
	}

	/* enable all safe decompression profiles */
	is_ok = rohc_decomp_enable_profiles(tunnel->decomp,
	                                    ROHC_PROFILE_UNCOMPRESSED,
	                                    ROHC_PROFILE_IP,
	                                    ROHC_PROFILE_UDP,
	                                    ROHC_PROFILE_RTP,
	                                    -1);
	if(!is_ok)
	{
		trace(LOG_ERR, "failed to enable profiles for decompressor");
		goto destroy_decomp;
	}

	tunnel->is_init = true;
	return true;

destroy_decomp:
	rohc_decomp_free(tunnel->decomp);
destroy_comp:
	rohc_comp_free(tunnel->comp);
free_packing_stats:
	free(tunnel->stats.stats_packing);
error:
	return false;
}


/**
 * @brief Reset the given tunnel context
 *
 * @param tunnel  The tunnel context to reset
 * @return        true if the tunnel was successfully reset,
 *                false if a problem occurred
 */
bool iprohc_tunnel_free(struct iprohc_tunnel *const tunnel)
{
	if(tunnel->is_init)
	{
		/* free the ROHC compressor and decompressor */
		rohc_decomp_free(tunnel->decomp);
		rohc_comp_free(tunnel->comp);

		/* reset RAW sockets and TUN fds: do not close them, they are shared with
		 * other clients */
		tunnel->tun_fd_in = -1;
		tunnel->tun_fd_out = -1;
		tunnel->raw_socket_in = -1;
		tunnel->raw_socket_out = -1;

		/* device MTU */
		tunnel->tun_itf_mtu = 0;
		tunnel->basedev_mtu = 0;

		/* no more parameter */
		memset(&tunnel->params, 0, sizeof(struct tunnel_params));

		/* reset stats */
		free(tunnel->stats.stats_packing);
		memset(&tunnel->stats, 0, sizeof(struct statitics));

		tunnel->is_init = false;
	}

	return true;
}


/**
 * @brief Start a new tunnel
 *
 * This function is intented to be started as a thread. It
 * will assume that the fields of tunnel are correctly filled,
 * specially that the tun and raw_socket are correctly opened
 *
 * This function will initialize ROHC contexts and start polling tun and
 * raw socket to compress/decompress the packets via the other functions.
 *
 * @param arg    A tunnel session
 * @return       NULL in case of success, a non-null value otherwise
 */
void * iprohc_tunnel_run(void *arg)
{
	struct iprohc_session *const session = (struct iprohc_session *) arg;
	struct iprohc_tunnel *const tunnel = &(session->tunnel);

	unsigned int verify_status;

	int failure = 0;
	int ret;

	struct timeval now;
	struct timeval last;
	bool is_last_init = false;

	size_t packing_cur_len = 0;  /* number of packed bytes */
	size_t packing_cur_pkts = 0;  /* number of packed frames */

	/* TODO : Check assumed present attributes
	   (thread, local_address, dest_address, tun, fake_tun, raw_socket) */

	tunnel_trace(session, LOG_INFO, "start of thread");

	/* initialize the last time we sent a packet */
	gettimeofday(&(session->last_activity), NULL);

	/* Get rid of warning, it's a "bug" of GnuTLS
	 * (see http://lists.gnu.org/archive/html/help-gnutls/2006-03/msg00020.html) */
	gnutls_transport_set_ptr_nowarn(session->tls_session, session->tcp_socket);

	/* perform TLS handshake */
	do
	{
		ret = gnutls_handshake(session->tls_session);
	}
	while(ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if(ret < 0)
	{
		tunnel_trace(session, LOG_ERR, "TLS handshake failed: %s (%d)",
		             gnutls_strerror(ret), ret);
		goto error;
	}
	tunnel_trace(session, LOG_INFO, "TLS handshake succeeded");

	/* check the peer certificate */
	ret = gnutls_certificate_verify_peers2(session->tls_session, &verify_status);
	if(ret < 0)
	{
		tunnel_trace(session, LOG_ERR, "TLS verify failed: %s (%d)",
		             gnutls_strerror(ret), ret);
		goto tls_bye;
	}
	if((verify_status & GNUTLS_CERT_INVALID) &&
	   (verify_status != (GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID)))
	{
		tunnel_trace(session, LOG_ERR, "certificate cannot be verified "
		             "(status %u)", verify_status);
		if(verify_status & GNUTLS_CERT_REVOKED)
		{
			tunnel_trace(session, LOG_ERR, "- revoked certificate");
		}
		if(verify_status & GNUTLS_CERT_SIGNER_NOT_FOUND)
		{
			tunnel_trace(session, LOG_ERR, "- unable to trust certificate issuer");
		}
		if(verify_status & GNUTLS_CERT_SIGNER_NOT_CA)
		{
			tunnel_trace(session, LOG_ERR, "- certificate issuer is not a CA");
		}
#ifdef GNUTLS_CERT_NOT_ACTIVATED
		if(verify_status & GNUTLS_CERT_NOT_ACTIVATED)
		{
			tunnel_trace(session, LOG_ERR, "- the certificate is not activated");
		}
#endif
#ifdef GNUTLS_CERT_EXPIRED
		if(verify_status & GNUTLS_CERT_EXPIRED)
		{
			tunnel_trace(session, LOG_ERR, "- the certificate has expired");
		}
#endif
		goto tls_bye;
	}
	trace(LOG_INFO, "remote certificate accepted");

	/* send initial control message to remote peer if asked to do so */
	if(session->start_ctrl != NULL)
	{
		if(!session->start_ctrl(session))
		{
			tunnel_trace(session, LOG_ERR, "failed to send initial control "
			             "message to remote peer");
			goto tls_bye;
		}
	}

	/* main loop of client */
	do
	{
		fd_set readfds;
		size_t timeout_orig;
		struct timeval timeout;
		int max_fd = 0;
		int ret;

		/* wait at most twice the keepalive timeout */
		timeout_orig = 80;
		if(session->status == IPROHC_SESSION_CONNECTED)
		{
			timeout_orig = session->tunnel.params.keepalive_timeout * 2;
		}
		timeout.tv_sec = timeout_orig;
		timeout.tv_usec = 0;

		/* sockets and file descriptors to monitor */
		FD_ZERO(&readfds);
		/* read side of the pipe */
		FD_SET(session->p2c[0], &readfds);
		max_fd = max(session->p2c[0], max_fd);
		/* TCP socket */
		FD_SET(session->tcp_socket, &readfds);
		max_fd = max(session->tcp_socket, max_fd);
		/* keepalive timer */
		FD_SET(session->keepalive_timer_fd, &readfds);
		max_fd = max(session->keepalive_timer_fd, max_fd);
		if(session->status == IPROHC_SESSION_CONNECTED)
		{
			/* TUN interface */
			FD_SET(tunnel->tun_fd_in, &readfds);
			max_fd = max(tunnel->tun_fd_in, max_fd);
			/* RAW socket */
			FD_SET(tunnel->raw_socket_in, &readfds);
			max_fd = max(tunnel->raw_socket_in, max_fd);
		}

		ret = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
		if(ret < 0)
		{
			tunnel_trace(session, LOG_ERR, "select failed: %s (%d)",
			             strerror(errno), errno);
			failure = 1;
			session->status = IPROHC_SESSION_PENDING_DELETE;
			goto tls_bye;
		}
		else if(ret == 0)
		{
			/* no event occurred */
			tunnel_trace(session, LOG_DEBUG, "select: no event occurred");
			continue;
		}

		/* stop thread if main thread closed the write side of the pipe */
		if(FD_ISSET(session->p2c[0], &readfds))
		{
			session->status = IPROHC_SESSION_PENDING_DELETE;
			goto tls_bye;
		}

		/* event on control channel? */
		if(FD_ISSET(session->tcp_socket, &readfds))
		{
			const size_t max_msg_len = 1024;
			unsigned char msg[max_msg_len];
			size_t msg_len;
			int ret;

			tunnel_trace(session, LOG_DEBUG, "read on control socket");
			ret = gnutls_record_recv(session->tls_session, msg, max_msg_len);
			if(ret < 0)
			{
				tunnel_trace(session, LOG_ERR, "failed to receive data from remote "
				             "peer on TLS session: %s (%d)", gnutls_strerror(ret), ret);
				session->status = IPROHC_SESSION_PENDING_DELETE;
				goto tls_bye;
			}
			else if(ret == 0)
			{
				tunnel_trace(session, LOG_ERR, "TLS session was interrupted by "
				             "remote peer");
				session->status = IPROHC_SESSION_PENDING_DELETE;
				goto tls_bye;
			}
			msg_len = ret;
			tunnel_trace(session, LOG_DEBUG, "[thread] received %zu byte(s) on TCP socket",
			             msg_len);

			/* handle request */
			if(!session->handle_ctrl_msg(session, msg, msg_len))
			{
				if(session->status == IPROHC_SESSION_CONNECTED)
				{
					tunnel_trace(session, LOG_NOTICE, "client was disconnected");
					session->status = IPROHC_SESSION_PENDING_DELETE;
					goto tls_bye;
				}
				else if(session->status == IPROHC_SESSION_CONNECTING)
				{
					tunnel_trace(session, LOG_NOTICE, "client failed to connect");
					session->status = IPROHC_SESSION_PENDING_DELETE;
					goto tls_bye;
				}
				assert(0); /* should not happen */
			}
			else if(session->status == IPROHC_SESSION_PENDING_DELETE)
			{
				tunnel_trace(session, LOG_INFO, "session closed");
				continue;
			}
			else
			{
				/* refresh last activity timestamp */
				gettimeofday(&(session->last_activity), NULL);

				/* re-arm keepalive timer */
				if(!iprohc_session_update_keepalive(session,
				                                    tunnel->params.keepalive_timeout))
				{
					tunnel_trace(session, LOG_ERR, "failed to update the keepalive "
					      "timeout to %zu seconds", tunnel->params.keepalive_timeout);
					session->status = IPROHC_SESSION_PENDING_DELETE;
					goto tls_bye;
				}
			}
		}

		/* send keepalive in case there is too few activity on control channel */
		if(FD_ISSET(session->keepalive_timer_fd, &readfds))
		{
			const char command[1] = { C_KEEPALIVE };
			uint64_t keepalive_timer_nr;

			ret = read(session->keepalive_timer_fd, &keepalive_timer_nr,
			           sizeof(uint64_t));
			if(ret < 0)
			{
				tunnel_trace(session, LOG_ERR, "failed to read keepalive timer: "
				             "%s (%d)", strerror(errno), errno);
				session->status = IPROHC_SESSION_PENDING_DELETE;
				goto tls_bye;
			}
			else if(ret != sizeof(uint64_t))
			{
				tunnel_trace(session, LOG_ERR, "failed to read keepalive timer: "
				             "received %d bytes while expecting %zu bytes",
				             ret, sizeof(uint64_t));
				session->status = IPROHC_SESSION_PENDING_DELETE;
				goto tls_bye;
			}

			trace(LOG_DEBUG, "send a keepalive command");
			gnutls_record_send(session->tls_session, command, 1);
		}

		/* bridge from TUN to RAW */
		if(session->status == IPROHC_SESSION_CONNECTED &&
		   FD_ISSET(tunnel->tun_fd_in, &readfds))
		{
			const size_t packing_max_len = tunnel->basedev_mtu - sizeof(struct iphdr);

			tunnel_trace(session, LOG_DEBUG, "received data from tun");
			failure = tun2raw(tunnel->comp, tunnel->tun_fd_in,
			                  tunnel->raw_socket_out, session->dst_addr,
			                  tunnel->basedev_mtu, tunnel->packing_frame,
			                  packing_max_len, &packing_cur_len,
			                  tunnel->params.packing, &packing_cur_pkts,
			                  &(tunnel->stats));
			gettimeofday(&last, NULL);
			is_last_init = true;
			if(failure)
			{
				tunnel_trace(session, LOG_NOTICE, "tun2raw failed");
			}
		}

		/* bridge from RAW to TUN */
		if(session->status == IPROHC_SESSION_CONNECTED &&
		   FD_ISSET(tunnel->raw_socket_in, &readfds))
		{
			tunnel_trace(session, LOG_DEBUG, "received data from raw");
			failure = raw2tun(tunnel->decomp, session->src_addr.s_addr,
			                  tunnel->raw_socket_in, tunnel->tun_fd_out,
			                  tunnel->basedev_mtu, &(tunnel->stats));
			if(failure)
			{
				tunnel_trace(session, LOG_NOTICE, "raw2tun failed");
			}
		}

		gettimeofday(&now, NULL);
		if(!is_last_init)
		{
			last = now;
			is_last_init = true;
		}
		if(now.tv_sec > last.tv_sec + timeout.tv_sec)
		{
			if(packing_cur_len > 0)
			{
				tunnel_trace(session, LOG_DEBUG, "no packets since a while, "
				             "flushing incomplete frame");
				send_puree(tunnel->raw_socket_out, session->dst_addr, tunnel->basedev_mtu,
				           tunnel->packing_frame, &packing_cur_len, &packing_cur_pkts,
				           &(tunnel->stats));
				assert(packing_cur_len == 0);
				assert(packing_cur_pkts == 0);
			}
		}

		if(now.tv_sec > session->last_activity.tv_sec + tunnel->params.keepalive_timeout)
		{
			tunnel_trace(session, LOG_ERR, "keepalive timeout detected "
			             "(%ld > %ld + %zu), disconnect client", now.tv_sec,
			             session->last_activity.tv_sec,
			             tunnel->params.keepalive_timeout);
			session->status = IPROHC_SESSION_PENDING_DELETE;
		}
	}
	while(session->status >= IPROHC_SESSION_CONNECTING);

	tunnel_trace(session, LOG_INFO, "client thread was asked to stop");

	/* send final control message to remote peer if asked to do so */
	if(session->stop_ctrl != NULL)
	{
		if(!session->stop_ctrl(session))
		{
			tunnel_trace(session, LOG_ERR, "failed to send final control "
			             "message to remote peer");
			goto tls_bye;
		}
	}

tls_bye:
	/* close TLS session */
	tunnel_trace(session, LOG_INFO, "close TLS session");
	gnutls_bye(session->tls_session, GNUTLS_SHUT_WR);
error:
	tunnel_trace(session, LOG_INFO, "end of thread");
	session->status = IPROHC_SESSION_PENDING_DELETE;
	AO_store_release_write(&(session->is_thread_running), 0);
	return NULL;
}


/**
 * @brief Send the current packet
 *
 * The function actually send to the RAW socket the send-to-be "floating"
 * packet. It is triggered:
 *  - when the packet contains \e packing packets (nominal case)
 *  - when including another packet would make this packet too big for MTU
 *  - when no packet were sent for 1 seconds
 *
 * @param to                The RAW socket descriptor to write to
 * @param raddr             The remote address of the tunnel
 * @param mtu               The MTU of the underlying network interface
 * @param compressed_packet Pointer to the send-to-be "floating" packet when
 *                          *act_comp = packing or timeout
 * @param total_size        Pointer to the total size of the send-to-be
 *                          "floating" packet
 * @param act_comp          Pointer to the current number of packet in packing
 * @param stats             The compression/decompression statistics
 */
int send_puree(int to,
               struct in_addr raddr,
               const size_t mtu,
               unsigned char *compressed_packet,
               size_t *total_size,
               size_t *act_comp,
               struct statitics *stats)
{
	int ret;
	struct sockaddr_in addr;

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = raddr.s_addr;

	dump_packet("Packet ROHC: ", compressed_packet, *total_size);
	stats->stats_packing[*act_comp] += 1;

	if((*total_size) > (mtu - sizeof(struct iphdr)))
	{
		trace(LOG_ERR, "Packet too big to be sent, abort");
		goto error;
	}

	/* write the ROHC packet in the RAW tunnel */
	trace(LOG_DEBUG, "Sending on raw socket to %s\n",  inet_ntoa(raddr));
	ret = sendto(to, compressed_packet, *total_size, 0,
	             (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
	if(ret < 0)
	{
		trace(LOG_ERR, "sendto failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}
	trace(LOG_DEBUG, "%zu bytes written on socket %d\n", *total_size, to);

	/* reset packing variables */
	*total_size = 0;
	*act_comp   = 0;
	return 0;

error:
	/* reset packing variables */
	*total_size = 0;
	*act_comp   = 0;
	trace(LOG_ERR, "write to raw failed\n");
	return -1;
}


/**
 * @brief Forward IP packets received on the TUN interface to the RAW socket
 *
 * The function compresses the IP packets thanks to the ROHC library before
 * sending them on the RAW socket.
 *
 * @param comp              The ROHC compressor
 * @param from              The TUN file descriptor to read from
 * @param to                The RAW socket descriptor to write to
 * @param raddr             The remote address of the tunnel
 * @param mtu               The MTU (in bytes) of the output interface
 * @param packing_frame     IN/OUT: The incomplete packing frame being built
 * @param packing_max_len   The max number of bytes in packing frame
 * @param packing_cur_len   IN/OUT: The current number of bytes in packing
 *                                  frame
 * @param packing_max_pkts  The max number of packets in packing frame
 * @param packing_cur_pkts  IN/OUT: The current number of packets in packing
 *                                  frame
 * @param stats             IN/OUT: The statistics of the current tunnel
 * @return                  0 in case of success, a non-null value otherwise
 */
int tun2raw(struct rohc_comp *comp,
            int from,
            int to,
            struct in_addr raddr,
            const size_t mtu,
            unsigned char *const packing_frame,
            const size_t packing_max_len,
            size_t *const packing_cur_len,
            const size_t packing_max_pkts,
            size_t *const packing_cur_pkts,
            struct statitics *stats)
{
	const struct rohc_timestamp arrival_time = { .sec = 0, .nsec = 0 };
	const size_t packing_header_len = 2;

	unsigned char buffer[TUNTAP_BUFSIZE];
	unsigned int buffer_len = TUNTAP_BUFSIZE;

	unsigned char rohc_packet_temp[TUNTAP_BUFSIZE];
	unsigned char *rohc_packet_p;
	size_t rohc_size;

	unsigned char *packet;
	unsigned int packet_len;

	rohc_comp_last_packet_info2_t last_packet_info;

	int ret;
	bool ok;

	/* sanity checks */
	assert(comp != NULL);
	assert(packing_frame != NULL);
	assert(packing_cur_len != NULL);
	assert(packing_cur_pkts != NULL);
	assert(packing_max_len > packing_header_len);
	assert(packing_max_pkts > 0);
	assert((*packing_cur_len) < packing_max_len);
	assert((*packing_cur_pkts) < packing_max_pkts);

	/* read the IP packet from the virtual interface */
	ret = read(from, buffer, buffer_len);
	if(ret < 0)
	{
		trace(LOG_ERR, "Read failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}
	buffer_len = ret;

	trace(LOG_DEBUG, "Read %u bytes on tun fd %d\n", ret, from);

	dump_packet("Read from tun", buffer, buffer_len);

	if(buffer_len == 0)
	{
		goto quit;
	}
	else if(buffer_len < sizeof(struct tun_pi))
	{
		trace(LOG_ERR, "tun2raw: drop invalid packet: too small for TUN header");
		goto quit;
	}

	/* We skip the 4 bytes TUN header */
	/* XXX : To be parametrized if fd is not tun */
	packet = buffer + sizeof(struct tun_pi);
	packet_len = buffer_len - sizeof(struct tun_pi);

	/* update stats */
	stats->comp_total++;

	/* compress the IP packet */
	ret = rohc_compress3(comp, arrival_time, packet, packet_len,
	                     rohc_packet_temp, MAX_ROHC_SIZE, &rohc_size);
	if(ret != ROHC_OK)
	{
		trace(LOG_ERR, "compression of packet failed (%d)\n", ret);
		goto error;
	}

	/* discard ROHC packets larger than the whole packing frame */
	if(rohc_size > (packing_max_len - packing_header_len))
	{
		trace(LOG_ERR, "discard too large compressed packet: packet is "
		      "%zd-byte long, but packing frame can only handle up to %zd-byte "
		      "packets\n", rohc_size, packing_max_len - packing_header_len);
		goto quit;
	}

	/* send current incomplete packing frame if the total size including the
	 * new ROHC packet will be over the MTU, thus making room for the new
	 * compressed packet */
	/* XXX : MTU should also be a parameter */
	if(((*packing_cur_len) + rohc_size + packing_header_len) >= packing_max_len)
	{
		send_puree(to, raddr, mtu, packing_frame, packing_cur_len,
		           packing_cur_pkts, stats);
		assert((*packing_cur_len) == 0);
		assert((*packing_cur_pkts) == 0);
	}

	trace(LOG_DEBUG, "Compress packet #%zd/%zd: %d bytes", *packing_cur_pkts,
	      packing_max_pkts, packet_len);
	/* Not very true, as the packet is already compressed, but the act_comp may
	 * have changed if the packet has ben sent because of the new size */

	/* rohc_packet_p will point the correct place for the new packet */
	rohc_packet_p = packing_frame + (*packing_cur_len);

	trace(LOG_DEBUG, "Packet #%zd/%zd compressed: %zd bytes",
	      *packing_cur_pkts, packing_max_pkts, rohc_size);
	dump_packet("Compressed packet", rohc_packet_temp, rohc_size);

	/* get packet statistics */
	/* Fill ROHC version */
	last_packet_info.version_major = 0;
	last_packet_info.version_minor = 0;
	ok = rohc_comp_get_last_packet_info2(comp, &last_packet_info);
	if(!ok)
	{
		trace(LOG_ERR, "Cannot get stats about the last compressed packet\n");
	}
	else
	{
		stats->head_comp_size    += last_packet_info.header_last_comp_size;
		stats->head_uncomp_size  += last_packet_info.header_last_uncomp_size;
		stats->total_comp_size   += last_packet_info.total_last_comp_size;
		stats->total_uncomp_size += last_packet_info.total_last_uncomp_size;
	}

	/* Addind size byte(s) */
	if(rohc_size >= 128)
	{
		/* over 128 => 2 bytes with the first bit to 1 and the length coded on 15 bits */
		*((uint16_t*) rohc_packet_p) = htons(rohc_size | (1 << 15));  /* 0b1000000000000000 */
		rohc_packet_p += 2;
		*packing_cur_len += 2;
	}
	else
	{
		/* under 128 => 1 bytes with the first bit to 0 and the length coded on 7 bits */
		*rohc_packet_p = rohc_size;
		rohc_packet_p += 1;
		*packing_cur_len += 1;
	}

	/* Copy newly compressed packet in "floating" packet */
	memcpy(rohc_packet_p, rohc_packet_temp, rohc_size);

	*packing_cur_len += rohc_size;
	(*packing_cur_pkts)++;

	if((*packing_cur_pkts) >= packing_max_pkts)
	{
		/* All packets loaded: GOGOGO */
		send_puree(to, raddr, mtu, packing_frame, packing_cur_len,
		           packing_cur_pkts, stats);
		assert((*packing_cur_len) == 0);
		assert((*packing_cur_pkts) == 0);
	}

quit:
	return 0;
error:
	stats->comp_failed++;
	return 1;
}


/**
 * @brief Forward ROHC packets received on the RAW socket to the TUN interface
 *
 * The function decompresses the ROHC packets thanks to the ROHC library before
 * sending them on the TUN interface.
 *
 * @param decomp    The ROHC decompressor
 * @param dst_addr  The IP destination address to filter traffic on
 * @param from      The RAW socket descriptor to read from
 * @param to        The TUN file descriptor to write to
 * @param mtu       The MTU (in bytes) of the input interface
 * @param stats     The decompression statistics
 * @return          0 in case of success, a non-null value otherwise
 */
int raw2tun(struct rohc_decomp *decomp,
				in_addr_t dst_addr,
				int from,
				int to,
				const size_t mtu,
				struct statitics *stats)
{
	const struct rohc_timestamp arrival_time = { .sec = 0, .nsec = 0 };

	unsigned char packet[TUNTAP_BUFSIZE];
	unsigned int packet_len = TUNTAP_BUFSIZE;
	struct iphdr *ip_header;

	unsigned char *ip_payload;
	size_t ip_payload_len;

	uint16_t csum;

	/* We add the 4 bytes of TUN headers */
	unsigned char decomp_packet[4 + MAX_ROHC_SIZE];

	int ret;
	int i = 0;

	/* read ROHC packet from the RAW tunnel */
	ret = read(from, packet, packet_len);
	if(ret < 0 || ret > packet_len)
	{
		trace(LOG_ERR, "recvfrom failed: %s (%d)\n", strerror(errno), errno);
		goto error_unpack;
	}
	if(ret == 0)
	{
		trace(LOG_ERR, "Empty packet received");
		goto ignore;
	}
	packet_len = ret;
	stats->total_received++;

	dump_packet("Decompressing: ", packet, packet_len);

	/* check that data is a valid IPv4 packet */
	if(packet_len <= 20)
	{
		trace(LOG_ERR, "bad packet received: too small for IPv4 header, "
		      "only %u bytes received", packet_len);
		goto error_unpack;
	}
	ip_header = (struct iphdr *) packet;
	if(ip_header->version != 4)
	{
		trace(LOG_ERR, "bad packet received: not IP version 4");
		goto error_unpack;
	}
	if(ip_header->ihl != 5)
	{
		trace(LOG_ERR, "bad packet received: IP options not supported");
		goto error_unpack;
	}
	csum = ip_fast_csum(packet, ip_header->ihl);
	if(csum != 0)
	{
		trace(LOG_ERR, "bad packet received: wrong IP checksum");
		goto error_unpack;
	}

	/* filter on IP destination address if asked */
	if(dst_addr != INADDR_ANY && ntohl(ip_header->daddr) != dst_addr)
	{
		trace(LOG_DEBUG, "filter out IP traffic with non-matching IP "
		      "destination address");
		goto ignore;
	}

	/* skip the IPv4 header */
	ip_payload = packet + (ip_header->ihl * 4);
	ip_payload_len = packet_len - (ip_header->ihl * 4);

	trace(LOG_DEBUG, "read one %zu-byte packed ROHC packet on RAW sock\n",
	      ip_payload_len);

	/* unpack, then decompress the ROHC packets */
	while(ip_payload_len > 0)
	{
		size_t decomp_size;
		int len;

		/* Get packet size */
		if(ip_payload[0] >= 128)
		{
			len = ntohs(*((uint16_t*) ip_payload)) & (~(1 << 15)); /* 0b0111111111111111 */;
			ip_payload += 2;
			ip_payload_len -= 2;
		}
		else
		{
			len = ip_payload[0];
			ip_payload += 1;
			ip_payload_len -= 1;
		}
		stats->decomp_total++;

		trace(LOG_DEBUG, "Packet #%d : %d bytes", i, len);
		i++;

		/* Some basic checks on packet length */
		if(len > MAX_ROHC_SIZE)
		{
			trace(LOG_ERR, "Packet too big, skipping");
			goto error_unpack;
		}

		if(len > ip_payload_len)
		{
			trace(LOG_ERR, "Packet bigger than containing packet, skipping all");
			goto error_unpack;
		}

		dump_packet("Packet: ", ip_payload, len);

		/* decompress the packet */
		ret = rohc_decompress2(decomp, arrival_time, ip_payload, len,
		                       &decomp_packet[4], MAX_ROHC_SIZE, &decomp_size);
		if(ret != ROHC_OK)
		{
			trace(LOG_ERR, "decompression of packet failed (%d)\n", ret);
			goto error;
		}

		/* build the TUN header */
		/* XXX : If not tun ?? */
		decomp_packet[0] = 0;
		decomp_packet[1] = 0;
		switch((decomp_packet[4] >> 4) & 0x0f)
		{
			case 4: /* IPv4 */
				decomp_packet[2] = 0x08;
				decomp_packet[3] = 0x00;
				break;
			case 6: /* IPv6 */
				decomp_packet[2] = 0x86;
				decomp_packet[3] = 0xdd;
				break;
			default:
				trace(LOG_ERR, "bad IP version (%d)\n",
				      (decomp_packet[4] >> 4) & 0x0f);
				goto error;
		}

		/* write the IP packet on the virtual interface */
		ret = write(to, decomp_packet, decomp_size + 4);
		if(ret < 0)
		{
			trace(LOG_ERR, "write failed: %s (%d)\n", strerror(errno), errno);
			goto error;
		}
		trace(LOG_DEBUG, "%u bytes written on fd %d\n", ret, to);

		ip_payload += len;
		ip_payload_len -= len;
	}

ignore:
	return 0;
error:
	stats->decomp_failed++;
	return -1;
error_unpack:
	stats->unpack_failed++;
	return -2;
}


/* Trace functions */

/**
 * @brief Display the content of a IP or ROHC packet
 *
 * This function is used for debugging purposes.
 *
 * @param descr   A string that describes the packet
 * @param packet  The packet to display
 * @param length  The length of the packet to display
 */
void dump_packet(char *descr, unsigned char *packet, unsigned int length)
{
	unsigned int i;
	char line[1024];
	char tmp[4];

	trace(LOG_DEBUG, "-------------------------------\n");
	trace(LOG_DEBUG, "%s (%u bytes):\n", descr, length);
	line[0] = '\0';
	for(i = 0; i < length; i++)
	{
		if(i > 0 && (i % 16) == 0)
		{
			trace(LOG_DEBUG, "%s", line);
			line[0] = '\0';
		}
		else if(i > 0 && (i % 8) == 0)
		{
			strcat(line, "\t");
		}
		snprintf(tmp, 4, "%.2x ", packet[i]);
		strcat(line, tmp);
	}
	if(line[0] != '\0')
	{
		trace(LOG_DEBUG, "%s", line);
	}
	trace(LOG_DEBUG, "-------------------------------\n");
}


/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param level    The priority level of the trace
 * @param entity   The entity that emitted the trace among:
 *                  \li ROHC_TRACE_COMP
 *                  \li ROHC_TRACE_DECOMP
 * @param profile  The ID of the ROHC compression/decompression profile
 *                 the trace is related to
 * @param format   The format string of the trace
 */
static void print_rohc_traces(rohc_trace_level_t level,
                              rohc_trace_entity_t entity,
                              int profile,
                              const char *format, ...)
{
	va_list args;
	int syslog_level;
	char*entity_s;
	char extended[MAX_TRACE_SIZE];
	char message[MAX_TRACE_SIZE];

	/* Bijection between ROHC levels and syslog ones */
	switch(level)
	{
		case ROHC_TRACE_DEBUG:
			syslog_level = LOG_DEBUG;
			break;
		case ROHC_TRACE_INFO:
			syslog_level = LOG_DEBUG;  /* intended, ROHC lib is too verbose */
			break;
		case ROHC_TRACE_WARNING:
			syslog_level = LOG_WARNING;
			break;
		case ROHC_TRACE_ERROR:
			syslog_level = LOG_ERR;
			break;
		case ROHC_TRACE_LEVEL_MAX:
			syslog_level = LOG_CRIT;
			break;
		default:
			syslog_level = LOG_ERR;
	}

	switch(entity)
	{
		case ROHC_TRACE_COMP:
			entity_s = "ROHC compressor";
			break;
		case ROHC_TRACE_DECOMP:
			entity_s = "ROHC decompressor";
			break;
		default:
			entity_s = "Unknown ROHC entity";
	}

	va_start(args, format);
	if(vsnprintf(extended, MAX_TRACE_SIZE, format, args) >= MAX_TRACE_SIZE)
	{
		trace(LOG_WARNING, "Following trace has been truncated\n");
	}
	va_end(args);

	if(strlen(extended) == 5 && extended[0] == '0' && extended[1] == 'x')
	{
		/* annoying packet dump trace, don't trace it */
		return;
	}

	if(snprintf(message, MAX_TRACE_SIZE, "%s[%d] : %s", entity_s, profile,
	            extended) >= MAX_TRACE_SIZE)
	{
		trace(LOG_WARNING, "Following trace has been truncated\n");
	}
	trace(syslog_level, "%s", message);
}


/**
 * @brief The RTP detection callback which do detect RTP stream
 *
 * @param ip           The inner ip packet
 * @param udp          The udp header of the packet
 * @param payload      The payload of the packet
 * @param payload_size The size of the payload (in bytes)
 * @param rtp_private  The optional private opaque context to help detecting
 *                     RTP streams
 * @return             true if the packet is an RTP packet, false otherwise
 */
bool callback_rtp_detect(const unsigned char *const ip,
                         const unsigned char *const udp,
                         const unsigned char *const payload,
                         const unsigned int payload_size,
                         void *const rtp_private)
{
	uint8_t rtp_version;
	bool is_rtp = false;

	const struct udphdr *udp_packet = (struct udphdr *) udp;

	/* check UDP destination port => range 10000 - 20000 fixed by asterisk */
	/* even is for RTP, odd for RTCP, so we check the parity               */
	if(ntohs(udp_packet->source) < 10000 ||
	   ntohs(udp_packet->source) > 20000 ||
	   ntohs(udp_packet->source) % 2 == 1)
	{
		trace(LOG_DEBUG, "RTP packet not detected (wrong UDP port (%d))\n", udp_packet->source);
		goto not_rtp;
	}

	/* check minimal RTP header length */
	if(payload_size < 12)
	{
		trace(LOG_DEBUG, "RTP packet not detected (UDP payload too short)\n");
		goto not_rtp;
	}

	/* check RTP version field */
	rtp_version = (*((uint8_t *) (payload)) & 0xA0) >> 6;  /* 0xA0 : 0b11000000 */
	if(rtp_version != 2)
	{
		trace(LOG_DEBUG, "RTP packet not detected (wrong RTP version)\n");
		goto not_rtp;
	}

	/* we think that the UDP packet is a RTP packet */
	trace(LOG_DEBUG, "RTP packet detected\n");
	is_rtp = true;

not_rtp:
	return is_rtp;
}


#if defined __GNUC__
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
#endif

static void gnutls_transport_set_ptr_nowarn(gnutls_session_t session, int ptr)
{
	return gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) ptr);
}

#if defined __GNUC__
#pragma GCC diagnostic error "-Wint-to-pointer-cast"
#endif


