#ifdef STATS_COLLECTD
#include <collectd/client.h>
#define COLLECTD_PATH "unix:/var/run/collectd-unixsock"

int collect_submit(lcc_connection_t * conn, lcc_identifier_t _id, struct timeval now, char* type, char* type_instance, int value)  ;
#endif


