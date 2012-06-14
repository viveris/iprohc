#include <unistd.h>
#include <sys/socket.h>

#include "tlv.h"
#include "keepalive.h"

#include "log.h"

/* Send a keepalive */
int keepalive(int socket)
{
	char command[1] = { C_KEEPALIVE } ;

	trace(LOG_DEBUG, "Keepalive !") ;
	return send(socket, command, 1, 0) ;
}
