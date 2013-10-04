cmake_minimum_required (VERSION 2.6)
project (IPROHC C)

add_definitions("-g")

option(BUILD_CLIENT "Build the ROHC IPIP client" ON)
option(BUILD_SERVER "Build the ROHC IPIP server" ON)
option(STATS_COLLECTD "Collect stats with collectd" OFF)

# Version number
set (IPROHC_VERSION_MAJOR 0)
set (IPROHC_VERSION_MINOR 7)
set (IPROHC_VERSION_BUGFIX 1)
if( EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.bzr" )
    message("Building from VCS sources")
    execute_process(COMMAND bzr revno
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    TIMEOUT 5
                    RESULT_VARIABLE bzr_result
                    OUTPUT_VARIABLE bzr_output)
    if( bzr_result EQUAL 0 )
        set (IPROHC_VERSION_REVNO ${bzr_output})
    else()
        set (IPROHC_VERSION_REVNO -1)
    endif()
else()
    message("Building from release sources")
    set (IPROHC_VERSION_REVNO 0)
endif()

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/iprohc.h.in ${CMAKE_CURRENT_BINARY_DIR}/iprohc.h)

add_subdirectory (common) 
if (BUILD_CLIENT)
    add_subdirectory (client) 
endif (BUILD_CLIENT)

if (BUILD_SERVER)
    add_subdirectory (server) 
endif (BUILD_SERVER)
