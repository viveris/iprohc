cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/")

find_package (Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})
find_package (ROHC REQUIRED)
set(LIBS ${LIBS} ${ROHC_LIBRARIES})

# Check for rtnl_talk prototype
include(CheckPrototypeDefinition)
check_prototype_definition(rtnl_talk
    "extern int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer, unsigned groups, struct nlmsghdr *answer)"
    "NULL"
    "stdlib.h;stdio.h;libnetlink.h"
    NEW_RTNL)

if (NEW_RTNL)
    message("Using new rtnl_talk prototype")
else (NEW_RTNL)
    message("Using old rtnl_talk prototype")
endif (NEW_RTNL)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

#

add_library (rohctunnel SHARED rohc_tunnel.c tun_helpers.c tlv.c)
add_definitions("-Wall")
target_link_libraries(rohctunnel ${LIBS} netlink) 

add_subdirectory (tests)
