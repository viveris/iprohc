cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/")

include_directories("../common")

add_executable (client client.c)

add_definitions("-Wall")

target_link_libraries(client rohctunnel ) 
