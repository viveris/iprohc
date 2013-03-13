cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../" ${CMAKE_CURRENT_SOURCE_DIR})

# Version number

set (IPROHC_SERVER_VERSION_MAJOR 0)
set (IPROHC_SERVER_VERSION_MINOR 4)

find_library(M_LIB m)
set(LIBS ${LIBS} ${M_LIB})

find_package (Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

find_package (GnuTLS REQUIRED)
set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})

find_package(Yaml REQUIRED)
set (LIBS ${LIBS} ${YAML_LIBRARIES})

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config_server.h.in ${CMAKE_CURRENT_BINARY_DIR}/config_server.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

if (STATS_COLLECTD)
    message("Stats with collectd enabled")
    set(LIBS ${LIBS} collectdclient)
else (STATS_COLLECTD)
    message("Stats with collectd disabled")
endif (STATS_COLLECTD)


include_directories("../common")

add_executable (iprohc_server server.c client.c messages.c tls.c config.c)

add_definitions("-Wall")

target_link_libraries(iprohc_server ${LIBS} iprohc_common) 

install(TARGETS iprohc_server DESTINATION bin)
