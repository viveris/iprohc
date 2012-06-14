#ifndef IPROHC_LOG_H
#define IPROHC_LOG_H

#include <syslog.h>
#include <stdarg.h>

extern int log_max_priority ;

static inline void trace(int priority, const char *format, ...) {
    va_list args ;
    
    if (priority <= log_max_priority) {
        va_start(args, format);
        vsyslog(LOG_MAKEPRI(LOG_DAEMON, priority), format, args) ;
        va_end(args);
    }

}

#endif
