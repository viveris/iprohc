/* rohc_tunnel.c -- Functions handling a tunnel, client or server-side

On a client connection :
 *

*/

#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>

#include "rohc_tunnel.h"

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>

/* Initialize logger */
#include <syslog.h>
#define MAX_LOG LOG_INFO
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)

/*
 * Macros & definitions:
 */

/// Return the greater value from the two
#define max(x, y)  (((x) > (y)) ? (x) : (y))

/// The maximal size of data that can be received on the virtual interface
#define TUNTAP_BUFSIZE 1518

/// The maximal size of a ROHC packet
#define MAX_ROHC_SIZE   (5 * 1024)

#define MAX_TRACE_SIZE 256

/* Prototypes for local functions */

void dump_packet(char *descr, unsigned char *packet, unsigned int length) ;
static void print_rohc_traces(rohc_trace_level_t level,
                              rohc_trace_entity_t entity,
                              int profile,
                              const char *format, ...)
                              __attribute__ ((format (printf, 4, 5)));
int callback_rtp_detect(const unsigned char *ip,
                        const struct udphdr *udp,
                        const unsigned char *payload,
                        const unsigned int payload_size,
                        void *rtp_private);

/* Main functions */
void send_puree(int to, struct in_addr raddr, unsigned char* compressed_packet, int* total_size, int* act_comp)
{
		int ret ;

		dump_packet("Packet ROHC : ", compressed_packet, *total_size) ;
		/* write the ROHC packet in the RAW tunnel */
		ret = write_to_raw(to, raddr, compressed_packet, *total_size);
		if(ret != 0)
		{
			trace(LOG_ERR, "write_to_raw failed\n");
		}
		*total_size = 0 ;
		*act_comp   = 0 ;
}

void* new_tunnel(void* arg) {

    struct tunnel* tunnel = (struct tunnel*) arg ;

    int failure = 0;
    int is_umode = tunnel->params.is_unidirectional ;

    fd_set readfds;
    struct timespec timeout;
    sigset_t sigmask;

    struct timeval last;
    struct timeval now;
    int kp_timeout = tunnel->params.keepalive_timeout ;
    int packing    = tunnel->params.packing ;

    int tun, raw;
    int ret;

    struct rohc_comp *comp;
    struct rohc_decomp *decomp;


    /* TODO : Check assumed present attributes
       (thread, local_address, dest_address, tun, fake_tun, raw_socket) */

    /* ROHC */
    /* create the compressor and activate profiles */
    comp = rohc_alloc_compressor(tunnel->params.max_cid, 0, 0, 0);
    if(comp == NULL)
    {
        trace(LOG_ERR, "cannot create the ROHC compressor\n");
        return NULL ;
    }
    rohc_activate_profile(comp, ROHC_PROFILE_UNCOMPRESSED);
    rohc_activate_profile(comp, ROHC_PROFILE_UDP);
    rohc_activate_profile(comp, ROHC_PROFILE_IP);
    rohc_activate_profile(comp, ROHC_PROFILE_UDPLITE);
    rohc_activate_profile(comp, ROHC_PROFILE_RTP);

    ret = rohc_comp_trace(comp, print_rohc_traces);
    if(ret != ROHC_OK) {
		trace(LOG_ERR, "cannot set trace callback for compressor\n") ;
		goto destroy_comp ;	
	} 


	ret = rohc_comp_set_rtp_detection_callback(comp, callback_rtp_detect, NULL) ;
	if(ret != ROHC_OK)
	{
		trace(LOG_ERR, "failed to set RTP detection callback\n");
		goto destroy_comp;
	}


    /* create the decompressor (associate it with the compressor) */
    decomp = rohc_alloc_decompressor(is_umode ? NULL : comp);
    if(decomp == NULL) {
        fprintf(stderr, "cannot create the ROHC decompressor\n");
        goto destroy_comp;
    }

    ret = rohc_decomp_trace(decomp, print_rohc_traces);
    if(ret != ROHC_OK) {
		trace(LOG_ERR, "cannot set trace callback for decompressor\n") ;
		goto destroy_decomp ;	
	}

    /* poll network interfaces each second */
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;

    /* mask signals during interface polling */
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGKILL);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGINT);

    /* initialize the last time we sent a packet */
    gettimeofday(&(tunnel->last_keepalive), NULL);
	tunnel->alive = 1 ;

	/* We read the fake TUN device if we are on a server */
	if (tunnel->fake_tun[0] == -1 && tunnel->fake_tun[1] == -1) {
		/* No fake_tun, we use the real TUN */
		tun = tunnel->tun ;
	} else {
		tun = tunnel->fake_tun[0] ; 
	}

	/* We read the fake raw device if we are on a server */
	if (tunnel->fake_raw[0] == -1 && tunnel->fake_raw[1] == -1) {
		/* No fake_raw, we use the real raw */
		raw = tunnel->raw_socket ;
	} else {
		raw = tunnel->fake_raw[0] ; 
	}

	int act_comp   = 0 ; /* Counter for packing */
	int total_size = 0 ; /* Size counter for packing */
	/* Max size is MAX_ROHC_SIZE + 2 bytes max for packet len multiplied by the packing */
	unsigned char* compressed_packet = calloc(packing*(MAX_ROHC_SIZE + 2), sizeof(char));


    do
    {
        /* poll the read sockets/file descriptors */
        FD_ZERO(&readfds);
        FD_SET(tun, &readfds);
        FD_SET(raw, &readfds);

        ret = pselect(max(tun, raw) + 1, &readfds, NULL, NULL, &timeout, &sigmask);
        if(ret < 0)
        {
            trace(LOG_ERR, "pselect failed: %s (%d)\n", strerror(errno), errno);
            failure = 1;
            tunnel->alive = 0;
        }
        else if(ret > 0)
        {
            trace(LOG_DEBUG, "Packet received...\n") ;
            /* bridge from TUN to RAW */
            if(FD_ISSET(tun, &readfds))
            {
                trace(LOG_DEBUG, "...from tun\n") ;
                trace(LOG_DEBUG, "Tunnel dest : %d\n", tunnel->dest_address.s_addr) ;
                failure = tun2raw(comp, tun, tunnel->raw_socket, tunnel->dest_address, &act_comp, packing, compressed_packet, &total_size);
                gettimeofday(&last, NULL);
                if(failure) {
                    trace(LOG_ERR, "tun2raw failed\n") ;
                    tunnel->alive = 0;
                }
            }
  
            /* bridge from RAW to TUN */
            if(FD_ISSET(raw, &readfds))
            {
                trace(LOG_DEBUG, "...from raw\n") ;
                failure = raw2tun(decomp, raw, tunnel->tun, packing);
                if(failure) {
                    trace(LOG_ERR, "raw2tun failed\n") ;
                    tunnel->alive = 0;
                }
            }
        }

		if (! FD_ISSET(tun, &readfds) && ! FD_ISSET(raw, &readfds)) {
			if (total_size > 0) {
				trace(LOG_DEBUG, "No packets since a while, sending...") ;
				send_puree(raw, tunnel->dest_address, compressed_packet, &total_size, &act_comp) ;
			}
		}

        gettimeofday(&now, NULL);
//        trace(LOG_DEBUG, "Keepalive : %ld vs. %ld + %d", now.tv_sec, tunnel->last_keepalive.tv_sec, kp_timeout) ;
        if(now.tv_sec > tunnel->last_keepalive.tv_sec + kp_timeout)
        {
            trace(LOG_ERR, "Keepalive timeout detected (%ld > %ld + %d), exiting", now.tv_sec, tunnel->last_keepalive.tv_sec, kp_timeout) ;
            tunnel->alive = 0 ;
        }
    }
    while(tunnel->alive > 0);

    /*
     * Cleaning:
     */

destroy_decomp:
    rohc_free_decompressor(decomp);
destroy_comp:
    rohc_free_compressor(comp);

	if (tunnel->close_callback != NULL) {
		tunnel->close_callback((void*) tunnel) ;
	}

    return NULL ;
}


int create_raw() {
    int sock ;

    /* create socket */
    sock = socket(AF_INET, SOCK_RAW, 142) ;
    if (sock < 0) {
        perror("Can't open RAW socket\n") ;
        goto quit ;
    }

	return sock ;

quit:
    return -1 ;
}


/**
 * @brief Forward IP packets received on the TUN interface to the RAW socket
 *
 * The function compresses the IP packets thanks to the ROHC library before
 * sending them on the RAW socket.
 *
 * @param comp   The ROHC compressor
 * @param from   The TUN file descriptor to read from
 * @param to     The RAW socket descriptor to write to
 * @param raddr  The remote address of the tunnel
 * @return       0 in case of success, a non-null value otherwise
 */
int tun2raw(struct rohc_comp *comp,
            int from, int to,
            struct in_addr raddr, 
            int* act_comp, int packing, unsigned char* compressed_packet,
            int* total_size)
{
	static unsigned char buffer[TUNTAP_BUFSIZE];
	unsigned int buffer_len = TUNTAP_BUFSIZE;

	unsigned char* rohc_packet_temp = calloc(MAX_ROHC_SIZE, sizeof(char));
	unsigned char *rohc_packet_p ; 

	unsigned char *packet;
	unsigned int packet_len;

	int rohc_size;

	int ret;

	/* read the IP packet from the virtual interface */
	ret = read_from_tun(from, buffer, &buffer_len);
	if(ret != 0)
	{
		trace(LOG_ERR, "read_from_tun failed\n");
		goto error;
	}
	dump_packet("Read from tun : ", buffer, buffer_len) ;

	if(buffer_len == 0)
		goto quit;
	

	/* We skip the 4 bytes TUN header */
	packet = &buffer[4];
	packet_len = buffer_len - 4;
	

	/* compress the IP packet */
	rohc_size = rohc_compress(comp, packet, packet_len,
							  rohc_packet_temp, MAX_ROHC_SIZE);
	if(rohc_size <= 0)
	{
		trace(LOG_ERR, "compression of packet failed\n");
		goto error;
	}

	if (*total_size + rohc_size + 4 > TUNTAP_BUFSIZE) {
		send_puree(to, raddr, compressed_packet, total_size, act_comp) ;
	}
	trace(LOG_DEBUG, "Compress packet #%d/%d : %d bytes", *act_comp, packing, packet_len) ;
	
	rohc_packet_p = compressed_packet + *total_size;
	
	trace(LOG_DEBUG, "Packet #%d/%d compressed : %d bytes", *act_comp, packing, rohc_size) ;
	dump_packet("Compressed packet", rohc_packet_temp, rohc_size) ;

	if (rohc_size > 128) {
		*((uint16_t*) rohc_packet_p) = htons(rohc_size | (1 << 15)) ; /* 0b1000000000000000 */
		rohc_packet_p += 2 ;
		*total_size   += 2 ; 
	} else {
		*rohc_packet_p = rohc_size ;
		rohc_packet_p += 1 ;
		*total_size   += 1 ; 
	}

	memcpy(rohc_packet_p, rohc_packet_temp, rohc_size) ;

	*total_size += rohc_size ;
	*act_comp = *act_comp + 1 ;

	if (*act_comp == packing) {
		send_puree(to, raddr, compressed_packet, total_size, act_comp) ;
	}

quit:
	return 0;
error:
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
int raw2tun(struct rohc_decomp *decomp, int from, int to, int packing)
{
	/* Max size is MAX_ROHC_SIZE + 2 bytes max for packet len multiplied by the packing */
	unsigned int packet_len = 20 + packing*(MAX_ROHC_SIZE+2) ;
	unsigned char* packet = calloc(packet_len, sizeof(unsigned char));
	unsigned char *packet_p = packet;

	/* We add the 4 bytes of TUN headers */
	unsigned char* decomp_packet = calloc(4 + MAX_ROHC_SIZE, sizeof(unsigned char));

	int len ;

	int decomp_size;
	int ret;

	/* read the sequence number + ROHC packet from the RAW tunnel */
	ret = read_from_raw(from, packet, &packet_len);
	if(ret != 0)
	{
		trace(LOG_ERR, "read_from_raw failed\n");
		goto error;
	}

	if(packet_len <= 20) {
		trace(LOG_ERR, "Bad packet received\n") ;
		goto quit;
	}

	dump_packet("Decompressing : ", packet + 20, packet_len - 20) ;
	/* decompress the ROHC packet */
	packet_p += 20 ;
	int i = 0;

	while(packet_p < packet + packet_len) {
		if (*packet_p >= 128) {
		    len = ntohs(*((uint16_t*) packet_p)) & (~(1 << 15)); /* 0b0111111111111111 */ ;
		    packet_p += 2 ;
		} else {
			len = *packet_p ;
		    packet_p += 1 ;
		}

		trace(LOG_DEBUG, "Packet #%d : %d bytes", i, len) ;
		i++ ;

		if (len > MAX_ROHC_SIZE) {
			trace(LOG_ERR, "Packet to big, skipping") ;
			continue ;
		}

		dump_packet("Packet : ", packet_p, len) ;
		decomp_size = rohc_decompress(decomp, packet_p, len,
									  &decomp_packet[4], MAX_ROHC_SIZE);
		if(decomp_size <= 0)
		{
			if(decomp_size == ROHC_FEEDBACK_ONLY)
			{
				/* no stats for feedback-only packets */
				goto quit;
			}
			else
			{
				trace(LOG_ERR, "decompression of packet failed\n");
				goto error;
			}
		}

		/* build the TUN header */
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
				goto drop;
		}

		/* write the IP packet on the virtual interface */
		ret = write_to_tun(to, decomp_packet, decomp_size + 4);
		if(ret != 0)
		{
			trace(LOG_ERR, "write_to_tun failed\n");
			goto drop ;
		}
	
drop:
		packet_p += len ;
	}
	

quit:
	return 0;

error:
	return 1;
}


int read_from_tun(int fd, unsigned char *packet, unsigned int *length)
{
    int ret;

    ret = read(fd, packet, *length);
    if(ret < 0 || ret > *length)
    {
        trace(LOG_ERR, "read failed: %s (%d)\n", strerror(errno), errno);
        goto error;
    }

    *length = ret;

    trace(LOG_DEBUG, "read %u bytes on tun fd %d\n", ret, fd);

    return 0;

error:
    *length = 0;
    return 1;
}


int write_to_tun(int fd, unsigned char *packet, unsigned int length)
{
    int ret;

    ret = write(fd, packet, length);
    if(ret < 0)
    {
        trace(LOG_ERR, "write failed: %s (%d)\n", strerror(errno), errno);
        goto error;
    }

    trace(LOG_DEBUG, "%u bytes written on fd %d\n", length, fd);

    return 0;

error:
    return 1;
}


int read_from_raw(int sock, unsigned char *buffer, unsigned int *length)
{
    int ret;

    /* read data from the RAW socket */
    ret = read(sock, buffer, *length);

    if(ret < 0 || ret > *length)
    {
        trace(LOG_ERR, "recvfrom failed: %s (%d)\n", strerror(errno), errno);
        goto error;
    }

    if(ret == 0) {
		trace(LOG_ERR, "recvfrom failed") ;
        goto quit;
    }

    *length = ret;

    trace(LOG_DEBUG, "read one %u-byte ROHC packet on RAW sock\n",*length);

quit:
    return 0;

error:
    *length = 0;
    return 1;
}

int write_to_raw(int sock, struct in_addr raddr, unsigned char *packet, unsigned int length)
{
    struct sockaddr_in addr;
    int ret;

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = raddr.s_addr;

    /* send the data on the RAW socket */
    trace(LOG_DEBUG, "Sending on raw socket to %s\n",  inet_ntoa(raddr)) ;
    ret = sendto(sock, packet, length, 0, (struct sockaddr *) &addr,
                 sizeof(struct sockaddr_in));
    if(ret < 0)
    {
        trace(LOG_ERR, "sendto failed: %s (%d)\n", strerror(errno), errno);
        goto error;
    }
    trace(LOG_DEBUG, "%u bytes written on socket %d\n", length, sock);

    return 0;

error:
    return 1;
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

    fprintf(stderr, "-------------------------------\n");
    fprintf(stderr, "%s (%u bytes):\n", descr, length);
    for(i = 0; i < length; i++)
    {
        if(i > 0 && (i % 16) == 0)
            fprintf(stderr, "\n");
        else if(i > 0 && (i % 8) == 0)
            fprintf(stderr, "\t");

        fprintf(stderr, "%.2x ", packet[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "-------------------------------\n");
}

/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param level    The priority level of the trace
 * @param entity   The entity that emitted the trace among:
 *                  \li ROHC_TRACE_COMPRESSOR
 *                  \li ROHC_TRACE_DECOMPRESSOR
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
	int syslog_level ;
	char* entity_s ;
	char extended[MAX_TRACE_SIZE] ;
	char message[MAX_TRACE_SIZE] ;

	/* Bijection between ROHC levels and syslog ones */
	switch (level) {
		case ROHC_TRACE_DEBUG:
			syslog_level = LOG_DEBUG ;
			break ;
		case ROHC_TRACE_INFO:
			syslog_level = LOG_INFO ;
			break;
		case ROHC_TRACE_WARNING:
			syslog_level = LOG_WARNING ;
			break ;
		case ROHC_TRACE_ERROR:
			syslog_level = LOG_ERR ;
			break;
		case ROHC_TRACE_LEVEL_MAX:
			syslog_level = LOG_CRIT ;
			break ;
		default:
			syslog_level = LOG_ERR ;
	}
	
	switch (entity) {
		case ROHC_TRACE_COMPRESSOR:
			entity_s = "ROHC compressor" ;	
			break ;
		case ROHC_TRACE_DECOMPRESSOR:
			entity_s = "ROHC decompressor" ;
			break ;
		default :
			entity_s = "Unknown ROHC entity" ;
	}

	va_start(args, format);
	if (vsnprintf(extended, MAX_TRACE_SIZE, format, args) >= MAX_TRACE_SIZE) {
		trace(LOG_WARNING, "Following trace has been truncated\n") ;
	}
	va_end(args);

	if (snprintf(message, MAX_TRACE_SIZE, "%s[%d] : %s", entity_s, profile, extended) >= MAX_TRACE_SIZE) {
		trace(LOG_WARNING, "Following trace has been truncated\n") ;
	}
	trace(syslog_level, message) ;
}
/**
 * @brief The RTP detection callback which do detect RTP stream
 *
 * @param ip           The inner ip packet
 * @param udp          The udp header of the packet
 * @param payload      The payload of the packet
 * @param payload_size The size of the payload (in bytes)
 * @return             1 if the packet is an RTP packet, 0 otherwise
 */
int callback_rtp_detect(const unsigned char *ip,
                        const struct udphdr *udp,
                        const unsigned char *payload,
                        const unsigned int payload_size,
                        void *rtp_private)
{
    uint8_t rtp_version;
    int is_rtp = 0;

    /* check UDP destination port => range 10000 - 20000 fixed by asterisk */
    /* even is for RTP, odd for RTCP, so we check the parity               */
    if (ntohs(udp->source)  < 10000 || ntohs(udp->source)  > 20000 || ntohs(udp->source) % 2 == 1)
    {
        trace(LOG_DEBUG, "RTP packet not detected (wrong UDP port (%d))\n", udp->source);
        goto not_rtp;
    }

    /* check minimal RTP header length */
    if(payload_size < 12)
    {
        trace(LOG_DEBUG, "RTP packet not detected (UDP payload too short)\n");
        goto not_rtp;
    }

    /* check RTP version field */
    rtp_version = (*((uint8_t *) (payload)) & 0xA0) >> 6; /* 0xA0 : 0b11000000 */
    if(rtp_version != 2)
    {
        trace(LOG_DEBUG, "RTP packet not detected (wrong RTP version)\n");
        goto not_rtp;
    }

    /* we think that the UDP packet is a RTP packet */
    trace(LOG_DEBUG, "RTP packet detected\n");
    is_rtp = 1;

not_rtp:
    return is_rtp;
}
