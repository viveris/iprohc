#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libnetlink.h>
#include <string.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/types.h>
#include <net/if.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>


#include <syslog.h>
#define MAX_LOG LOG_INFO
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)

#include "tun_helpers.h"

int set_link_up(char* dev)
{
	struct ifreq ifr;
    int fd;
    int err;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    err = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (err) {
        perror("SIOCGIFFLAGS");
        close(fd);
        return -1;
    }

	ifr.ifr_flags |= IFF_UP;
	err = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (err)
		perror("SIOCSIFFLAGS");
    close(fd);


    return err;
}

int get_device_id(char* dev, int* tun_itf_id)
{
	struct ifreq ifr;
    int fd;
    int err;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    err = ioctl(fd, SIOCGIFINDEX, &ifr);
    if (err) {
        perror("SIOCGIFFLAGS");
        close(fd);
        return -1;
    }
	
	*tun_itf_id = ifr.ifr_ifindex ;
	return 0 ;
}

int create_tun(char *name, int* tun_itf_id)
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
     *      IFF_TAP   - TAP device
     *      IFF_NO_PI - Do not provide packet information */
    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    ifr.ifr_flags = IFF_TUN | IFF_UP;

    /* create the TUN interface */
    if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
        trace(LOG_ERR, "failed to ioctl(TUNSETIFF) on /dev/net/tun: %s (%d)\n",
                strerror(errno), errno);
        close(fd);
        return err;
    }

	set_link_up(name) ;
	get_device_id(name, tun_itf_id) ;

    return fd;
}


int set_ip4(int iface_index, uint32_t address, uint8_t network)
{
	struct {
	   struct nlmsghdr  nh;
	   struct ifaddrmsg ip;
	   char            buf[256];
	} req;
	
	struct rtnl_handle rth = { .fd = -1 };
    if (rtnl_open(&rth, 0) < 0)
        exit(1);
	
	uint32_t* ip_data = calloc(8, sizeof(uint32_t));
	ip_data[0] = address ;


	/* initialize netlink request */
	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE|NLM_F_EXCL ;
	req.nh.nlmsg_type = RTM_NEWADDR;

	/* ifaddrmsg info */
	req.ip.ifa_family = AF_INET ;        /* IPv4 */
	req.ip.ifa_prefixlen = network ;    
    req.ip.ifa_index = iface_index ;

	addattr_l(&req.nh, sizeof(req), IFA_LOCAL,   ip_data, 4);
	addattr_l(&req.nh, sizeof(req), IFA_ADDRESS, ip_data, 4);

	/* GOGOGO */
	if (rtnl_talk(&rth, &req.nh, 0, 0, NULL) < 0) {
		return 1 ;
	}

	rtnl_close(&rth);
	return 0;
}



