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

#include "config.h" /* for RTNL_TALK_PARAMS */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <asm/types.h>
#include <fcntl.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip.h>
#include <libnetlink.h>

#include "log.h"
#include "tun_helpers.h"


/** The maximal size (in bytes) taken by the tunnel headers */
#define MAX_TUNNEL_OVERHEAD (sizeof(struct iphdr) + 2 + 20U)


/**
 * @brief Set the MTU of a new device wrt the MTU of its base device
 *
 * @param base_dev      The name of the base device
 * @param new_dev       The name of the new device
 * @param base_dev_mtu  OUT: The MTU of the base device
 * @param new_dev_mtu   OUT: The MTU of the new device
 * @return              true in case of success, false in case of failure
 */
bool set_link_mtu(const char *const base_dev,
                  const char *const new_dev,
                  size_t *const base_dev_mtu,
                  size_t *const new_dev_mtu)
{
	bool is_success = false;
	struct ifreq ifr;
	int fd;
	int err;

	assert(base_dev != NULL);
	assert(new_dev != NULL);
	assert(base_dev_mtu != NULL);
	assert(new_dev_mtu != NULL);

	/* open one INET socket to talk to the kernel */
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		trace(LOG_ERR, "failed to set MTU on interface '%s': failed to open "
		      "one INET socket: %s (%d)", new_dev, strerror(errno), errno);
		goto error;
	}

	/* get the MTU of the base device */
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, base_dev, IFNAMSIZ);
	err = ioctl(fd, SIOCGIFMTU, &ifr);
	if(err != 0)
	{
		trace(LOG_ERR, "failed to set MTU on interface '%s': failed to get MTU "
		      "of base interface '%s': %s (%d)", new_dev, base_dev,
		      strerror(errno), errno);
		goto close;
	}

	/* compute the new MTU */
	if(ifr.ifr_mtu <= 0 || ifr.ifr_mtu <= MAX_TUNNEL_OVERHEAD)
	{
		trace(LOG_ERR, "failed to set MTU on interface '%s': MTU of base "
		      "interface '%s' is too small: %d bytes while more than %u "
		      "bytes required", new_dev, base_dev, ifr.ifr_mtu,
		      MAX_TUNNEL_OVERHEAD);
		goto close;
	}
	*base_dev_mtu = ifr.ifr_mtu;
	*new_dev_mtu = ifr.ifr_mtu - MAX_TUNNEL_OVERHEAD;

	/* set the new MTU on the new device */
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, new_dev, IFNAMSIZ);
	ifr.ifr_mtu = *new_dev_mtu;
	err = ioctl(fd, SIOCSIFMTU, &ifr);
	if(err != 0)
	{
		trace(LOG_ERR, "failed to set MTU %zd on interface '%s': "
		      "ioctl(SIOCSIFMTU) failed: %s (%d)", *new_dev_mtu, new_dev,
		      strerror(errno), errno);
		goto close;
	}

	/* everything went fine */
	is_success = true;

close:
	close(fd);
error:
	return is_success;
}



int set_link_up(const char *const dev)
{
	struct ifreq ifr;
	int fd;
	int err;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		return -1;
	}
	err = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if(err)
	{
		trace(LOG_ERR, "failed to retrieve the flags of interface '%s': %s (%d)",
				ifr.ifr_name, strerror(errno), errno);
		close(fd);
		return -1;
	}

	ifr.ifr_flags |= IFF_UP;
	err = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if(err)
	{
		trace(LOG_ERR, "failed to update the flags of interface '%s': %s (%d)",
				ifr.ifr_name, strerror(errno), errno);
	}
	close(fd);

	return err;
}


int get_device_id(const char *const dev, int *const tun_itf_id)
{
	struct ifreq ifr;
	int fd;
	int err;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		return -1;
	}
	err = ioctl(fd, SIOCGIFINDEX, &ifr);
	if(err)
	{
		trace(LOG_ERR, "failed to retrieve the flags of interface '%s': %s (%d)",
				ifr.ifr_name, strerror(errno), errno);
		close(fd);
		return -1;
	}

	*tun_itf_id = ifr.ifr_ifindex;

	close(fd);
	return 0;
}


int create_tun(const char *const name,
               const char *const basedev,
               int *const tun_itf_id,
               size_t *const basedev_mtu,
               size_t *const tun_itf_mtu)
{
	struct ifreq ifr;
	int fd, err;

	assert(name != NULL);
	assert(basedev != NULL);
	assert(tun_itf_id != NULL);
	assert(basedev_mtu != NULL);
	assert(tun_itf_mtu != NULL);

	/* open a file descriptor on the kernel interface */
	if((fd = open("/dev/net/tun", O_RDWR)) < 0)
	{
		trace(LOG_ERR, "failed to open /dev/net/tun: %s (%d)\n",
		      strerror(errno), errno);
		goto error;
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
		goto close;
	}

	if(!set_link_mtu(basedev, name, basedev_mtu, tun_itf_mtu))
	{
		trace(LOG_ERR, "failed to create TUN interface '%s': failed to set MTU",
		      name);
		goto close;
	}
	trace(LOG_INFO, "MTU of underlying interface '%s' set to %zd bytes",
	      basedev, *basedev_mtu);
	trace(LOG_INFO, "MTU of tunnel interface '%s' set to %zd bytes", name,
	      *tun_itf_mtu);

	if(set_link_up(name) != 0)
	{
		trace(LOG_ERR, "failed to create TUN interface '%s': failed to set "
		      "link up", name);
		goto close;
	}

	if(get_device_id(name, tun_itf_id) != 0)
	{
		trace(LOG_ERR, "failed to create TUN interface '%s': failed to get "
		      "device ID", name);
		goto close;
	}

	return fd;

close:
	close(fd);
error:
	return -1;
}


bool set_ip4(int iface_index, uint32_t address, uint8_t network)
{
	bool is_success = false;
	int ret;
	struct {
		struct nlmsghdr nh;
		struct ifaddrmsg ip;
		char buf[256];
	} req;
	struct rtnl_handle rth = { .fd = -1 };
	uint32_t *ip_data;

	ret = rtnl_open(&rth, 0);
	if(ret < 0)
	{
		trace(LOG_ERR, "failed to open RTNL socket");
		goto error;
	}

	ip_data = calloc(8, sizeof(uint32_t));
	if(ip_data == NULL)
	{
		trace(LOG_ERR, "failed to allocate memory for setting IPv4 address");
		goto close_rtnl;
	}
	ip_data[0] = address;

	/* initialize netlink request */
	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.nh.nlmsg_type = RTM_NEWADDR;

	/* ifaddrmsg info */
	req.ip.ifa_family = AF_INET;         /* IPv4 */
	req.ip.ifa_prefixlen = network;
	req.ip.ifa_index = iface_index;

	addattr_l(&req.nh, sizeof(req), IFA_LOCAL,   ip_data, 4);
	addattr_l(&req.nh, sizeof(req), IFA_ADDRESS, ip_data, 4);

	/* GOGOGO */
#if RTNL_TALK_PARAMS == 5
	ret = rtnl_talk(&rth, &req.nh, 0, 0, NULL);
#elif RTNL_TALK_PARAMS == 7
	ret = rtnl_talk(&rth, &req.nh, 0, 0, NULL, NULL, NULL);
#else
#  error "unsupported version of rtnl_talk()"
#endif
	if(ret < 0)
	{
		trace(LOG_ERR, "failed to set IPv4 address");
		goto free_ip_data;
	}

	is_success = true;

free_ip_data:
	free(ip_data);
close_rtnl:
	rtnl_close(&rth);
error:
	return is_success;
}


int create_raw(void)
{
	int sock;

	/* create socket */
	sock = socket(AF_INET, SOCK_RAW, 142);
	if(sock < 0)
	{
		trace(LOG_ERR, "failed to create a raw socket: %s (%d)",
				strerror(errno), errno);
		goto quit;
	}

	return sock;

quit:
	return -1;
}


