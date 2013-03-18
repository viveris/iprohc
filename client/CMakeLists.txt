cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../")

# Version

set (IPROHC_CLIENT_VERSION_MAJOR 0)
set (IPROHC_CLIENT_VERSION_MINOR 4)


find_package (GnuTLS REQUIRED)
set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})

include_directories("../common")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config_client.h.in ${CMAKE_CURRENT_BINARY_DIR}/config_client.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable (iprohc_client client.c messages.c tls.c)

add_definitions("-Wall -Wno-deprecated -Wno-deprecated-declarations")

target_link_libraries(iprohc_client iprohc_common ${LIBS}) 

install (TARGETS iprohc_client DESTINATION bin)
