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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "tlv.h"
#include <syslog.h>

int main(int argc, char*argv[])
{
	struct tunnel_params params;
	struct tunnel_params params2;
	char tlv[1024];
//	int i ;
	/* Initialize logger */
	openlog("test_tlv_connect", LOG_PID | LOG_PERROR, LOG_DAEMON);


	params.local_address       = 392407232;
	params.packing             = 5;
	params.max_cid             = 14;
	params.is_unidirectional   = 0;
	params.wlsb_window_width   = 23;
	params.refresh             = 9;
	params.keepalive_timeout   = 1000;
	params.rohc_compat_version = 1;

	printf("Genetating tlv\n");
	gen_connect(tlv, params);
	printf("Done genetating...\n");
/*	for (i=0; i<100; i++) {
      printf("%x.", tlv[i]) ;
   } */
	printf("Parsing tlv\n");
	parse_connect(tlv, &params2);
	printf("Done parsing tlv\n");

	printf("params.local_address : %d\n", params2.local_address);
	printf("params.packing : %d\n", params2.packing);
	printf("params.max_cid : %ld\n", params2.max_cid);
	printf("params.is_unidirectional : %d\n", params2.is_unidirectional);
	printf("params.wlsb_window_width : %ld\n", params2.wlsb_window_width);
	printf("params.refresh : %ld\n", params2.refresh);
	printf("params.keepalive_timeout : %ld\n", params2.keepalive_timeout);
	printf("params.rohc_compat_version : %d\n", params2.rohc_compat_version);

	return 0;
}


