#include <unistd.h>
#include <sys/socket.h>

#include "tlv.h"
#include "keepalive.h"

#include <syslog.h>
#define MAX_LOG LOG_INFO
#define trace(a, ...) if ((a) & MAX_LOG) syslog(LOG_MAKEPRI(LOG_DAEMON, a), __VA_ARGS__)

int keepalive(int socket)
{
	char command[1] = { C_KEEPALIVE } ;

	trace(LOG_DEBUG, "Keepalive !") ;
	return send(socket, command, 1, 0) ;
}
