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

#ifdef STATS_COLLECTD
#include <collectd/client.h>
#define COLLECTD_PATH "unix:/var/run/collectd-unixsock"

int collect_submit(lcc_connection_t *conn, lcc_identifier_t _id, struct timeval now, char*type,
                   char*type_instance,
                   int value);
#endif


