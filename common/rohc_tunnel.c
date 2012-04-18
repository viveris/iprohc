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

/* Main functions */

void* new_tunnel(void* arg) {

    struct tunnel* tunnel = (struct tunnel*) arg ;
    int alive ;

    int failure = 0;
    int is_umode = 1 ; /* TODO : Handle other mode */

    fd_set readfds;
    struct timespec timeout;
    sigset_t sigmask;

    struct timeval last;
    struct timeval now;

    int tun;
    int ret;

    struct rohc_comp *comp;
    struct rohc_decomp *decomp;

    /* TODO : Check assumed present attributes
       (thread, local_address, dest_address, tun, fake_tun) */

    /*  Create raw socket */
    tunnel->raw_socket = create_socket() ;
    if (tunnel->raw_socket < 0) {
        perror("Unable to open raw socket") ;
        /* TODO : Handle error */
    }

    /* ROHC */
    /* create the compressor and activate profiles */
    comp = rohc_alloc_compressor(15, 0, 0, 0);
    if(comp == NULL)
    {
        trace(LOG_ERR, "cannot create the ROHC compressor\n");
        goto close_raw;
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
    gettimeofday(&last, NULL);
	alive = 1 ;
    do
    {
        /* poll the read sockets/file descriptors */
        FD_ZERO(&readfds);
        FD_SET(tunnel->tun, &readfds);
        FD_SET(tunnel->raw_socket, &readfds);

        ret = pselect(max(tunnel->tun, tunnel->raw_socket) + 1, &readfds, NULL, NULL, &timeout, &sigmask);
        if(ret < 0)
        {
            trace(LOG_ERR, "pselect failed: %s (%d)\n", strerror(errno), errno);
            failure = 1;
            alive = 0;
        }
        else if(ret > 0)
        {
            trace(LOG_DEBUG, "Packet received...\n") ;
            /* bridge from TUN to RAW */
            if(FD_ISSET(tunnel->tun, &readfds))
            {
                trace(LOG_DEBUG, "...from tun...\n") ;
                /* We read the fake TUN device if we are on a server */
                if (tunnel->fake_tun[0] == -1 && tunnel->fake_tun[1] == -1) {
                    /* No fake_tun, we use the real TUN */
                    trace(LOG_DEBUG, "...which is a true tun\n") ;
                    tun = tunnel->tun ;
                } else {
                    trace(LOG_DEBUG, "...which is a fake tun\n") ;
                    tun = tunnel->fake_tun[0] ; 
                }
                trace(LOG_DEBUG, "Tunnel dest : %d\n", tunnel->dest_address.s_addr) ;
                failure = tun2raw(comp, tun, tunnel->raw_socket, tunnel->dest_address);
                gettimeofday(&last, NULL);
                if(failure) {
                    trace(LOG_ERR, "tun2raw failed\n") ;
                    alive = 0;
                }
            }
  
            /* bridge from RAW to TUN */
            if(FD_ISSET(tunnel->raw_socket, &readfds))
            {
                trace(LOG_DEBUG, "...from raw\n") ;
                failure = raw2tun(decomp, tunnel->raw_socket, tunnel->tun);
                if(failure) {
                    trace(LOG_ERR, "raw2tun failed\n") ;
                    alive = 0;
                }
            }
        }

        /* flush feedback data if nothing is sent in the tunnel for a moment */
        gettimeofday(&now, NULL);
        if(now.tv_sec > last.tv_sec + 1)
        {
            trace(LOG_INFO, "It's been a while since I sent my last packet") ;
/*            failure = flush_feedback(comp, tunnel->raw_socket, ;
            last = now;
#if STOP_ON_FAILURE
            if(failure)
                alive = 0;
#endif */
        }
    }
    while(alive);

    /*
     * Cleaning:
     */

destroy_decomp:
    rohc_free_decompressor(decomp);
destroy_comp:
    rohc_free_compressor(comp);

close_raw:
    close(tunnel->raw_socket) ;
    return NULL ;
}


int create_socket() {
    int sock ;

    /* create socket */
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_IPIP) ;
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
            struct in_addr raddr)
{
	static unsigned char buffer[TUNTAP_BUFSIZE];
	static unsigned char rohc_packet[MAX_ROHC_SIZE];
	unsigned int buffer_len = TUNTAP_BUFSIZE;
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

	packet = &buffer[4];
	packet_len = buffer_len - 4;

	/* compress the IP packet */
	trace(LOG_DEBUG, "compress packet (%u bytes)\n", packet_len);
	rohc_size = rohc_compress(comp, packet, packet_len,
	                          rohc_packet, MAX_ROHC_SIZE);
	if(rohc_size <= 0)
	{
		trace(LOG_ERR, "compression of packet failed\n");
		goto error;
	}

	dump_packet("Packet ROHC : ", rohc_packet, rohc_size) ;
	/* write the ROHC packet in the RAW tunnel */
    ret = write_to_raw(to, raddr, rohc_packet, rohc_size);
    if(ret != 0)
    {
        trace(LOG_ERR, "write_to_raw failed\n");
        goto error;
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
int raw2tun(struct rohc_decomp *decomp, int from, int to)
{
	static unsigned char packet[MAX_ROHC_SIZE];
	static unsigned char decomp_packet[MAX_ROHC_SIZE + 4];
	unsigned int packet_len = MAX_ROHC_SIZE;
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
	fprintf(stderr, "decompress ROHC packet (%u bytes)\n", packet_len - 20);
	decomp_size = rohc_decompress(decomp, packet + 20, packet_len - 20,
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
			goto drop;
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
			fprintf(stderr, "bad IP version (%d)\n",
			        (decomp_packet[4] >> 4) & 0x0f);
			goto drop;
	}
	
	/* write the IP packet on the virtual interface */
	ret = write_to_tun(to, decomp_packet, decomp_size + 4);
	if(ret != 0)
	{
		fprintf(stderr, "write_to_tun failed\n");
		goto drop;
	}

drop:
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
    struct sockaddr_in addr;
    socklen_t addr_len;
    int ret;

    addr_len = sizeof(struct sockaddr_in);
    bzero(&addr, addr_len);

    /* read data from the RAW socket */
    ret = recvfrom(sock, buffer, *length, 0, (struct sockaddr *) &addr,
                   &addr_len);

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

