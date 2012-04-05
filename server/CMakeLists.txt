cmake_minimum_required (VERSION 2.6)
find_package (Threads)

add_executable (server server.c)

target_link_libraries(server ${CMAKE_THREAD_LIBS_INIT}) 
