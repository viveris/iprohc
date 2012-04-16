#include <stdint.h>


int create_tun(char *name, int* tun_itf_id) ;
int set_ip4(int iface_index, uint32_t address, uint8_t network);
//int set_link_up(char* dev);
