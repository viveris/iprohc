cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/")

find_package (Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

include_directories("../common")

add_executable (server server.c client.c messages.c)

add_definitions("-Wall")

target_link_libraries(server ${LIBS} rohctunnel ) 
