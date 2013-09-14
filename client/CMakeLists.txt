cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../")

message("Checking for GnuTLS")
find_package (GnuTLS REQUIRED)
set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})

message("Checking for ROHC")
find_package (ROHC REQUIRED 1.6.0)
include_directories(${ROHC_INCLUDE_DIR})
link_directories(${ROHC_LIBRARIES_DIR})
add_definitions(${ROHC_DEFINITIONS})
set(LIBS ${LIBS} ${ROHC_LIBRARIES})

include_directories("../common")

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/..)

add_executable (iprohc_client client.c messages.c tls.c)

add_definitions("-Wall ${CFLAGS}")

target_link_libraries(iprohc_client iprohc_common ${LIBS}) 

install (TARGETS iprohc_client DESTINATION bin)
