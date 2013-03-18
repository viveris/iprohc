# - Try to find ROHC
# Once done this will define
#  ROHC_FOUND - System has ROHC
#  ROHC_INCLUDE_DIRS - The ROHC include directories
#  ROHC_LIBRARIES - The libraries needed to use ROHC
#  ROHC_DEFINITIONS - Compiler switches required for using ROHC

find_package(PkgConfig)

pkg_check_modules(PC_ROHC rohc)

if (PC_ROHC_FOUND)
    set(ROHC_DEFINITIONS ${PC_ROHC_CFLAGS_OTHER})
    set(ROHC_LIBRARIES ${PC_ROHC_LIBRARIES} )
    set(ROHC_INCLUDE_DIR ${PC_ROHC_INCLUDE_DIRS})

    ## handle the QUIETLY and REQUIRED arguments and set ROHC_FOUND to TRUE
    ## if all listed variables are TRUE
    find_package_handle_standard_args(ROHC DEFAULT_MSG
                                      PC_ROHC_VERSION)
else (PC_ROHC_FOUND)
    FIND_PACKAGE_MESSAGE(ROHC "Unable to find pkgconfig for ROHC, trying to find it directly" "")
    find_path(ROHC_INCLUDE_DIR rohc.h )

    find_library(ROHC_LIBRARY_COMMON NAMES rohc_common)
    find_library(ROHC_LIBRARY_COMP NAMES rohc_comp)
    find_library(ROHC_LIBRARY_DECOMP NAMES rohc_decomp)
    set(ROHC_LIBRARIES ${ROHC_LIBRARY_COMMON} ${ROHC_LIBRARY_COMP} ${ROHC_LIBRARY_DECOMP} )
    include(FindPackageHandleStandardArgs)
    ## handle the QUIETLY and REQUIRED arguments and set ROHC_FOUND to TRUE
    ## if all listed variables are TRUE
    find_package_handle_standard_args(ROHC DEFAULT_MSG
                                      ROHC_LIBRARIES ROHC_INCLUDE_DIR)
endif (PC_ROHC_FOUND)

set(ROHC_INCLUDE_DIRS ${ROHC_INCLUDE_DIR} )

mark_as_advanced(ROHC_INCLUDE_DIRS ROHC_LIBRARIES )
