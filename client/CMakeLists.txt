cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/")

include_directories("../common")

add_executable (rohc_ipip_client client.c messages.c)

add_definitions("-Wall")

target_link_libraries(rohc_ipip_client rohc_ipip_common) 

install (TARGETS rohc_ipip_client DESTINATION bin)
