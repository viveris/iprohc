cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/")

find_package (GnuTLS REQUIRED)
set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})

include_directories("../common")

add_executable (iprohc_client client.c messages.c tls.c)

add_definitions("-Wall")

target_link_libraries(iprohc_client iprohc_common ${LIBS}) 

install (TARGETS iprohc_client DESTINATION bin)
