cmake_minimum_required (VERSION 2.6)
project (RoHCIPIPtunnel)

add_definitions("-g")

option(BUILD_CLIENT "Build the ROHC IPIP client" ON)
option(BUILD_SERVER "Build the ROHC IPIP server" ON)

add_subdirectory (common) 
if (BUILD_CLIENT)
    add_subdirectory (client) 
endif (BUILD_CLIENT)

if (BUILD_SERVER)
    add_subdirectory (server) 
endif (BUILD_SERVER)
