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

#include "rohc_tunnel.h"

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>
#include <rohc_traces.h>

#include "ip_chksum.h"

/* Initialize logger */
#include "log.h"

#include "config.h"

#include "stats.h"


/*
 * Macros & definitions:
 */

/// Return the greater value from the two
#define max(x, y)  (((x) > (y)) ? (x) : (y))

/// The maximal size of data that can be received on the virtual interface
#define TUNTAP_BUFSIZE 1518

/// The maximal size of data that can be sent on the raw socket
#define RAW_BUFSIZE 1450

/// The maximal size of a ROHC packet
#define MAX_ROHC_SIZE   (5 * 1024)

#define MAX_TRACE_SIZE 256

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
               unsigned char *compressed_packet,
               int *total_size,
               int *act_comp,
               struct statitics *stats);
int raw2tun(struct rohc_decomp *decomp,
            in_addr_t dst_addr,
            int from,
            int to,
            int packing,
            struct statitics *stats);
int tun2raw(struct rohc_comp *comp,
            int from,
            int to,
            struct in_addr raddr,
            int *act_comp,
            int packing,
            unsigned char *compressed_packet,
            int *total_size,
            struct statitics *stats);
#ifdef STATS_COLLECTD
#include <collectd/client.h>

int collect_submit(lcc_connection_t *conn,
                   lcc_identifier_t _id,
                   struct timeval now,
                   char *type,
                   char *type_instance,
                   int value)
{
	lcc_identifier_t id = _id;
	lcc_value_list_t vals;

	/* All types are gauge (for the moment) */
	value_t values[1];
	values[0].gauge = value;
	vals.values = values;
	int types[] = { LCC_TYPE_GAUGE };
	vals.values_types = types;
	vals.values_len = 1;

	/* Set time and interval */
	vals.time     = now.tv_sec;
	vals.interval = 1;

	/* Set strings type */
	strncpy(id.type, type, strlen(type));
	strncpy(id.type_instance, type_instance, strlen(type_instance));
	vals.identifier = id;

	return lcc_putval(conn, &vals);
}


int collect_stats(struct statitics stats, struct timeval now, struct in_addr addr)
{
	lcc_connection_t *conn;
	lcc_identifier_t id = { "localhost", "iprohc", "", "bytes", "" };
	int i;

	trace(LOG_DEBUG, "Sending stats");

	strncpy(id.plugin_instance, inet_ntoa(addr), LCC_NAME_LEN);

	if(lcc_connect(COLLECTD_PATH, &conn) < 0)
	{
		return -1;
	}

	if(collect_submit(conn, id, now, "bytes", "decomp-failed",     stats.decomp_failed)     < 0)
	{
		goto error;
	}
	if(collect_submit(conn, id, now, "bytes", "decomp-total",      stats.decomp_total)      < 0)
	{
		goto error;
	}
	if(collect_submit(conn, id, now, "bytes", "comp_failed",       stats.comp_failed)       < 0)
	{
		goto error;
	}
	if(collect_submit(conn, id, now, "bytes", "comp_total",        stats.comp_total)        < 0)
	{
		goto error;
	}
	if(collect_submit(conn, id, now, "bytes", "head_comp_size",    stats.head_comp_size)    < 0)
	{
		goto error;
	}
	if(collect_submit(conn, id, now, "bytes", "head_uncomp_size",  stats.head_uncomp_size)  < 0)
	{
		goto error;
	}
	if(collect_submit(conn, id, now, "bytes", "total_comp_size",   stats.total_comp_size)   < 0)
	{
		goto error;
	}
	if(collect_submit(conn, id, now, "bytes", "total_uncomp_size", stats.total_uncomp_size) < 0)
	{
		goto error;
	}
	if(collect_submit(conn, id, now, "bytes", "unpack_failed",     stats.unpack_failed)     < 0)
	{
		goto error;
	}
	if(collect_submit(conn, id, now, "bytes", "total_received",    stats.total_received)    < 0)
	{
		goto error;
	}

	for(i = 0; i < stats.n_stats_packing; i++)
	{
		char name[LCC_NAME_LEN];
		snprintf(name, LCC_NAME_LEN, "packing-%d", i);
		if(collect_submit(conn, id, now, "gauge", name,  stats.stats_packing[i]) < 0)
		{
			goto error;
		}
	}

	LCC_DESTROY(conn);

	return 0;

error:
	LCC_DESTROY(conn);
	return -1;
}

#endif


/*
 * Main functions
 */

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
 * @param arg    A struct tunnel defining tunnel itself
 * @return       0 in case of success, a non-null value otherwise
 */
void * new_tunnel(void *arg)
{
	struct tunnel*tunnel = (struct tunnel*) arg;

	int failure = 0;
	int is_umode = tunnel->params.is_unidirectional;

	fd_set readfds;
	struct timespec timeout;
	sigset_t sigmask;

	struct timeval now;
	struct timeval last;
	bool is_last_init = false;
#ifdef STATS_COLLECTD
	struct timeval last_stat;
#endif

	int kp_timeout   = tunnel->params.keepalive_timeout;
	int packing      = tunnel->params.packing;

	int read_tun, read_raw;
	int ret;

	struct rohc_comp *comp;
	struct rohc_decomp *decomp;



	/* TODO : Check assumed present attributes
	   (thread, local_address, dest_address, tun, fake_tun, raw_socket) */

	/*
	 * ROHC
	 */

	/* create the compressor and activate profiles */
	comp = rohc_alloc_compressor(tunnel->params.max_cid, 0, 0, 0);
	if(comp == NULL)
	{
		trace(LOG_ERR, "cannot create the ROHC compressor");
		goto error;
	}
	rohc_activate_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
	rohc_activate_profile(comp, ROHC_PROFILE_UDP);
	rohc_activate_profile(comp, ROHC_PROFILE_IP);
	rohc_activate_profile(comp, ROHC_PROFILE_UDPLITE);
	rohc_activate_profile(comp, ROHC_PROFILE_RTP);

	/* handle compressor trace */
	ret = rohc_comp_set_traces_cb(comp, print_rohc_traces);
	if(ret != ROHC_OK)
	{
		trace(LOG_ERR, "cannot set trace callback for compressor");
		goto destroy_comp;
	}

	/* set RTP callback for detecting RTP packets */
	ret = rohc_comp_set_rtp_detection_cb(comp, callback_rtp_detect, NULL);
	if(ret != ROHC_OK)
	{
		trace(LOG_ERR, "failed to set RTP detection callback");
		goto destroy_comp;
	}


	/* create the decompressor (associate it with the compressor) */
	decomp = rohc_alloc_decompressor(is_umode ? NULL : comp);
	if(decomp == NULL)
	{
		trace(LOG_ERR, "cannot create the ROHC decompressor");
		goto destroy_comp;
	}

	/* handle compressor trace */
	ret = rohc_decomp_set_traces_cb(decomp, print_rohc_traces);
	if(ret != ROHC_OK)
	{
		trace(LOG_ERR, "cannot set trace callback for decompressor");
		goto destroy_decomp;
	}

	/* poll network interfaces each 200 ms */
	timeout.tv_sec = 0;
	timeout.tv_nsec = 200 * 1000 * 1000;

	/* mask signals during interface polling */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGKILL);
	sigaddset(&sigmask, SIGTERM);
	sigaddset(&sigmask, SIGINT);

	/* initialize the last time we sent a packet */
	gettimeofday(&(tunnel->last_keepalive), NULL);
	tunnel->alive = 1;

	/* We read the fake TUN device if we are on a server */
	if(tunnel->fake_tun[0] == -1 && tunnel->fake_tun[1] == -1)
	{
		/* No fake_tun, we use the real TUN */
		read_tun = tunnel->tun;
	}
	else
	{
		read_tun = tunnel->fake_tun[0];
	}

	/* We read the fake raw device if we are on a server */
	if(tunnel->fake_raw[0] == -1 && tunnel->fake_raw[1] == -1)
	{
		/* No fake_raw, we use the real raw */
		read_raw = tunnel->raw_socket;
	}
	else
	{
		read_raw = tunnel->fake_raw[0];
	}

	/* Initialize stats */
	tunnel->stats.decomp_failed     = 0;
	tunnel->stats.decomp_total      = 0;
	tunnel->stats.comp_failed       = 0;
	tunnel->stats.comp_total        = 0;
	tunnel->stats.head_comp_size    = 0;
	tunnel->stats.head_uncomp_size  = 0;
	tunnel->stats.total_comp_size   = 0;
	tunnel->stats.total_uncomp_size = 0;
	tunnel->stats.unpack_failed     = 0;
	tunnel->stats.total_received    = 0;
	tunnel->stats.n_stats_packing   = packing + 1;
	tunnel->stats.stats_packing     = calloc(tunnel->stats.n_stats_packing, sizeof(int));
#ifdef STATS_COLLECTD
	gettimeofday(&last_stat, NULL);
#endif

	/* Initalize packing */
	int act_comp   = 0;  /* Counter for packing */
	int total_size = 0;  /* Size counter for packing */
	/* Max size is MAX_ROHC_SIZE + 2 bytes max for packet len multiplied by the packing */
	unsigned char*compressed_packet = malloc(RAW_BUFSIZE * sizeof(char));

	do
	{
		/* poll the read sockets/file descriptors */
		FD_ZERO(&readfds);
		FD_SET(read_tun, &readfds);
		FD_SET(read_raw, &readfds);

		ret = pselect(max(read_tun, read_raw) + 1, &readfds, NULL, NULL,
		              &timeout, &sigmask);
		if(ret < 0)
		{
			trace(LOG_ERR, "pselect failed: %s (%d)\n", strerror(errno), errno);
			failure = 1;
			tunnel->alive = 0;
		}
		else if(ret > 0)
		{
			trace(LOG_DEBUG, "Packet received...\n");
			/* bridge from TUN to RAW */
			if(FD_ISSET(read_tun, &readfds))
			{
				trace(LOG_DEBUG, "...from tun\n");
				failure = tun2raw(comp, read_tun, tunnel->raw_socket,
				                  tunnel->dest_address, &act_comp, packing,
				                  compressed_packet, &total_size,
				                  &(tunnel->stats));
				gettimeofday(&last, NULL);
				is_last_init = true;
				if(failure)
				{
					trace(LOG_ERR, "tun2raw failed\n");
					/* tunnel->alive = 0; */
				}
			}

			/* bridge from RAW to TUN */
			if(FD_ISSET(read_raw, &readfds))
			{
				trace(LOG_DEBUG, "...from raw\n");
				failure = raw2tun(decomp, tunnel->src_address.s_addr, read_raw,
				                  tunnel->tun, packing, &(tunnel->stats));
				if(failure)
				{
					trace(LOG_ERR, "raw2tun failed\n");
					/* tunnel->alive = 0; */
				}
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
			if(total_size > 0)
			{
				trace(LOG_DEBUG, "No packets since a while, sending...");
				send_puree(tunnel->raw_socket, tunnel->dest_address,
				           compressed_packet, &total_size, &act_comp,
				           &(tunnel->stats));
			}
		}
		if(now.tv_sec > tunnel->last_keepalive.tv_sec + kp_timeout)
		{
			trace(LOG_ERR, "Keepalive timeout detected (%ld > %ld + %d), exiting",
			      now.tv_sec, tunnel->last_keepalive.tv_sec, kp_timeout);
			tunnel->alive = 0;
		}

#ifdef STATS_COLLECTD
		if(now.tv_sec > last_stat.tv_sec + 1)
		{
			if(collect_stats(tunnel->stats, now, tunnel->dest_address) < 0)
			{
				trace(LOG_ERR, "Unable to submit stats");
			}
			gettimeofday(&last_stat, NULL);
		}
#endif
	}
	while(tunnel->alive > 0);

	trace(LOG_INFO, "client thread was asked to stop");

	/*
	 * Cleaning:
	 */
	free(compressed_packet);

destroy_decomp:
	rohc_free_decompressor(decomp);
destroy_comp:
	rohc_free_compressor(comp);
error:
	return NULL;
}


/**
 * @brief Send the current packet
 *
 * The function actually send to the RAW socket the send-to-be "floating" packet.
 * It is triggered : - when the packet contains #packing packets (nominal case)
 *                   - when including another packet would make this packet too big for MTU
 *                   - when no packet were sent for 1 seconds
 *
 * @param to                The RAW socket descriptor to write to
 * @param raddr             The remote address of the tunnel
 * @param compressed_packet Pointer to the send-to-be "floating" packet when *act_comp == packing or timeout
 * @param total_size        Pointer to the total size of the send-to-be "floating" packet
 * @param act_comp          Pointer to the current number of packet in packing
 */
int send_puree(int to,
               struct in_addr raddr,
               unsigned char *compressed_packet,
               int *total_size,
               int *act_comp,
               struct statitics *stats)
{
	int ret;
	struct sockaddr_in addr;

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = raddr.s_addr;

	dump_packet("Packet ROHC: ", compressed_packet, *total_size);
	stats->stats_packing[*act_comp] += 1;

	if(*total_size > RAW_BUFSIZE)
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
	trace(LOG_DEBUG, "%u bytes written on socket %d\n", *total_size, to);

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
 * @param act_comp          Pointer to the current number of packet in packing
 * @param packing           The max number of packets in packing (*act_comp <= packing)
 * @param compressed_packet Pointer to the send-to-be "floating" packet when *act_comp == packing or timeout
 * @param total_size        Pointer to the total size of the send-to-be "floating" packet
 * @param stats             Pointer to the statistics of the current tunnel
 * @return                  0 in case of success, a non-null value otherwise
 */
int tun2raw(struct rohc_comp *comp,
            int from,
            int to,
            struct in_addr raddr,
            int *act_comp,
            int packing,
            unsigned char *compressed_packet,
            int *total_size,
            struct statitics *stats)
{
	unsigned char buffer[TUNTAP_BUFSIZE];
	unsigned int buffer_len = TUNTAP_BUFSIZE;

	unsigned char*rohc_packet_temp = malloc(MAX_ROHC_SIZE * sizeof(char));
	unsigned char *rohc_packet_p;

	unsigned char *packet;
	unsigned int packet_len;

	rohc_comp_last_packet_info2_t last_packet_info;

	size_t rohc_size;
	int comp_result;

	int ret;
	bool ok;

	/* read the IP packet from the virtual interface */
	ret = read(from, buffer, buffer_len);
	if(ret < 0 || ret > buffer_len)
	{
		trace(LOG_ERR, "Read failed: %s (%d)\n", strerror(errno), errno);
		goto error;
	}
	buffer_len = ret;

	trace(LOG_DEBUG, "Read %u bytes on tun fd %d\n", ret, from);

	dump_packet("Read from tun: ", buffer, buffer_len);

	if(buffer_len == 0)
	{
		goto quit;
	}

	/* We skip the 4 bytes TUN header */
	/* XXX : To be parametrized if fd is not tun */
	packet = &buffer[4];
	packet_len = buffer_len - 4;

	/* update stats */
	stats->comp_total++;

	/* compress the IP packet */
	comp_result = rohc_compress2(comp, packet, packet_len,
	                             rohc_packet_temp, MAX_ROHC_SIZE, &rohc_size);
	if(comp_result != ROHC_OK)
	{
		trace(LOG_ERR, "compression of packet failed\n");
		goto error;
	}

	/* send current "floating" packet if the total size including the new packet will be
	   over the MTU, thus making room for the new compressed packet */
	/* XXX : MTU should also be a parameter */
	if(*total_size + rohc_size + 4 >= RAW_BUFSIZE - 20)
	{
		send_puree(to, raddr, compressed_packet, total_size, act_comp, stats);
	}

	trace(LOG_DEBUG, "Compress packet #%d/%d: %d bytes", *act_comp, packing, packet_len);
	/* Not very true, as the packet is already compressed, but the act_comp may
	 * have changed if the packet has ben sent because of the new size */

	/* rohc_packet_p will point the correct place for the new packet */
	rohc_packet_p = compressed_packet + *total_size;

	trace(LOG_DEBUG, "Packet #%d/%d compressed: %d bytes", *act_comp, packing, rohc_size);
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
		*total_size   += 2;
	}
	else
	{
		/* under 128 => 1 bytes with the first bit to 0 and the length coded on 7 bits */
		*rohc_packet_p = rohc_size;
		rohc_packet_p += 1;
		*total_size   += 1;
	}

	/* Copy newly compressed packet in "floating" packet */
	memcpy(rohc_packet_p, rohc_packet_temp, rohc_size);

	*total_size += rohc_size;
	*act_comp = *act_comp + 1;

	if(*act_comp == packing)
	{
		/* All packets loaded: GOGOGO */
		send_puree(to, raddr, compressed_packet, total_size, act_comp, stats);
	}

quit:
	free(rohc_packet_temp);
	return 0;
error:
	stats->comp_failed++;
	free(rohc_packet_temp);
	return 1;
}


/**
 * @brief Forward ROHC packets received on the RAW socket to the TUN interface
 *
 * The function decompresses the ROHC packets thanks to the ROHC library before
 * sending them on the TUN interface.
 *
 * @param decomp  The ROHC decompressor
 * @param from    The RAW socket descriptor to read from
 * @param to      The TUN file descriptor to write to
 * @return        0 in case of success, a non-null value otherwise
 */
int raw2tun(struct rohc_decomp *decomp,
				in_addr_t dst_addr,
				int from,
				int to,
				int packing,
				struct statitics *stats)
{
	unsigned int packet_len = RAW_BUFSIZE;
	unsigned char *packet = malloc(packet_len * sizeof(unsigned char));
	struct iphdr *ip_header;

	unsigned char *ip_payload;
	size_t ip_payload_len;

	uint16_t csum;

	/* We add the 4 bytes of TUN headers */
	unsigned char*decomp_packet = malloc((4 + MAX_ROHC_SIZE) * sizeof(unsigned char));

	int decomp_size;
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

	trace(LOG_DEBUG, "read one %u-byte packed ROHC packet on RAW sock\n",
	      ip_payload_len);

	/* unpack, then decompress the ROHC packets */
	while(ip_payload_len > 0)
	{
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
		decomp_size = rohc_decompress(decomp, ip_payload, len,
		                              &decomp_packet[4], MAX_ROHC_SIZE);
		if(decomp_size <= 0)
		{
			trace(LOG_ERR, "decompression of packet failed\n");
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
	free(packet);
	free(decomp_packet);
	return 0;
error:
	free(packet);
	free(decomp_packet);
	stats->decomp_failed++;
	return -1;
error_unpack:
	free(packet);
	free(decomp_packet);
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
			trace(LOG_DEBUG, line);
			line[0] = '\0';
		}
		else if(i > 0 && (i % 8) == 0)
		{
			strcat(line, "\t");
		}
		snprintf(tmp, 4, "%.2x ", packet[i]);
		strcat(line, tmp);
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
	trace(syslog_level, message);
}


/**
 * @brief The RTP detection callback which do detect RTP stream
 *
 * @param ip           The inner ip packet
 * @param udp          The udp header of the packet
 * @param payload      The payload of the packet
 * @param payload_size The size of the payload (in bytes)
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

