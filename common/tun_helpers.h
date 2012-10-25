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

#include <stdint.h>

#ifndef ROHC_IPIP_TUNH_H
#define ROHC_IPIP_TUNH_H

int create_tun(char *name, int* tun_itf_id) ;
int set_ip4(int iface_index, uint32_t address, uint8_t network);
int create_raw() ;

#endif
