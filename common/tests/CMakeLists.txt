cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/")

include_directories("../")

add_executable (test_tlv_connect test_tlv_connect.c)

add_definitions("-Wall")

target_link_libraries(test_tlv_connect rohc_ipip_common) 
