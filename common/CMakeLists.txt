cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/"
    "${CMAKE_CURRENT_SOURCE_DIR}/..")

message("Checking for threads")
find_package (Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

message("Checking for ROHC")
find_package (ROHC REQUIRED 1.7.0)
include_directories(${ROHC_INCLUDE_DIR})
link_directories(${ROHC_LIBRARIES_DIR})
add_definitions(${ROHC_DEFINITIONS})
set(LIBS ${LIBS} ${ROHC_LIBRARIES})


#
# Check for libnetlink
#

message("Checking for libnetlink")

# Check for libnetlink.h header file
find_file(HAVE_LIBNETLINK_H "libnetlink.h")
if (HAVE_LIBNETLINK_H STREQUAL "")
    message(FATAL_ERROR "libnetlink.h not found, please install the "
            "development package of iproute2")
else ()
    message(STATUS "Header libnetlink.h found at ${HAVE_LIBNETLINK_H}")
endif ()

# Check for rtnl_talk prototype
include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES "netlink")
check_c_source_compiles("#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <libnetlink.h>
int main(int argc, char* argv[]){rtnl_talk(NULL, NULL, 0, 0, NULL);}" NEW_RTNL)

if (NEW_RTNL)
    message(STATUS "Using new rtnl_talk prototype")
else (NEW_RTNL)
    message(STATUS "Using old rtnl_talk prototype")
endif (NEW_RTNL)


#
# Check for collectd
#

message("Checking for collectd")

if (STATS_COLLECTD)
	message(STATUS "Stats with collectd enabled")
    set(LIBS ${LIBS} collectdclient)
else (STATS_COLLECTD)
	message(STATUS "Stats with collectd disabled")
endif (STATS_COLLECTD)



CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/iprohc_common.h.in ${CMAKE_CURRENT_BINARY_DIR}/iprohc_common.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/.. ${ROHC_INCLUDE_DIRS})

add_library (iprohc_common SHARED rohc_tunnel.c tun_helpers.c tlv.c)
add_definitions("-Wall ${CFLAGS}")
target_link_libraries(iprohc_common ${LIBS} netlink) 

install (TARGETS iprohc_common DESTINATION lib)
install (FILES  rohc_tunnel.h  tlv.h  tun_helpers.h 
        DESTINATION include/iprohc_common/) 

option (BUILD_TEST "Also build test programs" OFF)

if (BUILD_TEST)
    add_subdirectory (tests)
endif (BUILD_TEST)
