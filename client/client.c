/* client.c -- Implements client side of the ROHC IP-IP tunnel
*/


#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/if_tun.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <syslog.h>

#include "rohc_tunnel.h"


#define TUNTAP_BUFSIZE 1518

#define MAX_LOG LOG_INFO
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)

/* Create TCP socket for communication with server */
int create_tcp_socket(uint32_t address, uint16_t port) {

	int sock = socket(AF_INET, SOCK_STREAM, 0) ;

	struct	sockaddr_in servaddr ;
	servaddr.sin_family	  = AF_INET;
	servaddr.sin_addr.s_addr = address;
	servaddr.sin_port		= htons(port);

	if (connect(sock,  (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
		perror("Connect failed") ;
	
	return sock ;
}

int create_tun(char *name)
{
	struct ifreq ifr;
	int fd, err;

	/* open a file descriptor on the kernel interface */
	if((fd = open("/dev/net/tun", O_RDWR)) < 0)
	{
		trace(LOG_ERR, "failed to open /dev/net/tun: %s (%d)\n",
				strerror(errno), errno);
		return fd;
	}

	/* flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *		IFF_TAP   - TAP device
	 *		IFF_NO_PI - Do not provide packet information */
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_flags = IFF_TUN;

	/* create the TUN interface */
	if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
	{
		trace(LOG_ERR, "failed to ioctl(TUNSETIFF) on /dev/net/tun: %s (%d)\n",
				strerror(errno), errno);
		close(fd);
		return err;
	}

	return fd;
}

int main(int argc, char *argv[]) {
	/* Initialize logger */
	openlog("rohc_ipip_client", LOG_PID | LOG_PERROR, LOG_DAEMON) ;

    uint32_t serv_addr = htonl(inet_network("127.0.0.1")) ;
	
	int socket = create_tcp_socket(serv_addr, 1989) ;
	printf("Dummy usage of socket %d\n", socket) ;

	int tun = create_tun("tun42") ;

	trace(LOG_DEBUG, "Creation of tunnel") ;

	/* Tunnel definition */
	struct tunnel tunnel ;
	set_ip("tun42", "192.168.99.23") ;

	/* dest addr */
	struct in_addr serv;
	serv.s_addr = serv_addr ;
	tunnel.dest_address = serv ;

	/* local_addr */
	struct in_addr local;
	local.s_addr = htonl(inet_network("192.168.99.23")) ;
	tunnel.local_address = local ;

	/* set tun */
	tunnel.tun = tun ; /* real tun device */
	tunnel.fake_tun[0] = 0 ;
	tunnel.fake_tun[1] = 0 ;
 
	/* Go go go ! */
	new_tunnel(&tunnel) ;

	return 1 ;
}
