cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../" ${CMAKE_CURRENT_SOURCE_DIR})

find_library(M_LIB m)
set(LIBS ${LIBS} ${M_LIB})

message("Checking for threads")
find_package (Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

message("Checking for ROHC")
find_package (ROHC REQUIRED 1.7.0)
include_directories(${ROHC_INCLUDE_DIR})
link_directories(${ROHC_LIBRARIES_DIR})
add_definitions(${ROHC_DEFINITIONS})
set(LIBS ${LIBS} ${ROHC_LIBRARIES})

message("Checking for GnuTLS")
find_package (GnuTLS REQUIRED)
set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})

message("Checking for libyaml")
find_package(Yaml REQUIRED)
set (LIBS ${LIBS} ${YAML_LIBRARIES})

include_directories(${CMAKE_CURRENT_BINARY_DIR})

if (STATS_COLLECTD)
    message("Stats with collectd enabled")
    set(LIBS ${LIBS} collectdclient)
else (STATS_COLLECTD)
    message("Stats with collectd disabled")
endif (STATS_COLLECTD)


include_directories("../common")
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/..)

add_executable (iprohc_server server.c client.c messages.c tls.c config.c)

add_definitions("-Wall ${CFLAGS}")

target_link_libraries(iprohc_server ${LIBS} iprohc_common) 

install(TARGETS iprohc_server DESTINATION bin)
