cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/")

find_package (Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})
find_package (ROHC REQUIRED)
set(LIBS ${LIBS} ${ROHC_LIBRARIES})

add_library (rohctunnel SHARED rohc_tunnel.c)

add_definitions("-Wall")

target_link_libraries(rohctunnel ${LIBS} ) 
