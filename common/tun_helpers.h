#include <stdint.h>

#ifndef ROHC_IPIP_TUNH_H
#define ROHC_IPIP_TUNH_H

int create_tun(char *name, int* tun_itf_id) ;
int set_ip4(int iface_index, uint32_t address, uint8_t network);

#endif
