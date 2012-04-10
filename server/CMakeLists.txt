cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/")

find_package (Threads REQUIRED)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})
find_package (ROHC REQUIRED)
set(LIBS ${LIBS} ${ROHC_LIBRARIES})

add_executable (server server.c handle_client.c)

target_link_libraries(server ${LIBS} ) 
