cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../" ${CMAKE_CURRENT_SOURCE_DIR})

find_package (Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

find_package (GnuTLS REQUIRED)
set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})

find_package(Yaml REQUIRED)
set (LIBS ${LIBS} ${YAML_LIBRARIES})

include_directories("../common")

add_executable (iprohc_server server.c client.c messages.c tls.c config.c)

add_definitions("-Wall")

target_link_libraries(iprohc_server ${LIBS} iprohc_common) 

install(TARGETS iprohc_server DESTINATION bin)
install(TARGETS iprohc_server.conf DESTINATION etc)
