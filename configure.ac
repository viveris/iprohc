#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# Process this file with autoconf to produce a configure script.
#
# Authors: Didier Barvaux <didier@barvaux.org>
#

AC_INIT([IP/ROHC tunnel], 0.8.0, [http://rohc-lib.org/],
        [iprohc], [http://rohc-lib.org/])
AC_CONFIG_SRCDIR([src])
AM_CONFIG_HEADER([config.h])

# Retrieve the Bazaar revision number
if test -d "$srcdir/.bzr" ; then
	bzr="`which bzr`"
	if test $? -ne 0 ; then
		PACKAGE_REVNO="~unknown"
	else
		PACKAGE_REVNO="~`${bzr} revno`"
	fi
elif test -f "$srcdir/bzr_revno" ; then
	PACKAGE_REVNO="`cat $srcdir/bzr_revno`"
else
	PACKAGE_REVNO=""
fi
AC_SUBST(PACKAGE_REVNO)
AC_DEFINE_UNQUOTED([PACKAGE_REVNO], ["$PACKAGE_REVNO"],
                   [Bazaar revision number])

# Define a package homepage in a way compatible with autoconf < 2.64
m4_ifndef([AC_PACKAGE_URL],
          [AC_DEFINE([PACKAGE_URL], ["http://rohc-lib.org/"],
                     [Define to home page for this package])
           AC_SUBST([PACKAGE_URL], ["http://rohc-lib.org/"])])

# Init automake with:
#  - silent rules enabled to make 'make' less verbose, but do not call the
#    AM_SILENT_RULES macro if it is not defined to keep compatibility with
#    automake < 1.11 for the moment.
#  - color-tests to get nice colored results for tests (currently disabled
#    to keep compatibility with automake 1.10 for the moment.
#  - prefer bzip2 over gzip for dist tarballs
#  - tar-ustar to allow paths that exceeds 99 characters in the dist tarball
AM_INIT_AUTOMAKE([foreign no-dist-gzip dist-bzip2 tar-pax parallel-tests])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Init libtool:
#  - require >= 2.2.0,
#  - disable static libraries by default,
#  - ready for Windows DLL
LT_PREREQ([2.2.0])
LT_INIT([disable-static win32-dll])

# CFLAGS/LDFLAGS default values, more will be added on purpose
configure_cflags="-g -Wall -Wstrict-prototypes"
configure_ldflags=""

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADERS([stdio.h stdlib.h string.h])
AC_CHECK_HEADERS([time.h sys/time.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([linux/if_tun.h]) # TUN/TAP support
AC_CHECK_HEADERS([sys/timerfd.h]) # timerfd support on Linux

# TUN interfaces are not supported on non-Linux platforms yet
if test "x$ac_cv_header_linux_if_tun_h" != "xyes" ; then
	echo
	echo "ERROR: non Linux platforms not supported yet"
	echo
	exit 1
fi

# timerfd API is mandatory
if test "x$ac_cv_header_sys_timerfd_h" != "xyes" ; then
	echo
	echo "ERROR: timerfd API is mandatory"
	echo
	exit 1
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_BIGENDIAN
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = "xno" ; then
	echo
	echo "ERROR: your compiler cannot run in C99 mode"
	echo
	echo "Please use another compiler or tweak compiler options and try again."
	exit 1
fi

# Checks for library functions.
AC_CHECK_FUNCS([malloc calloc free memcpy memcmp])
AC_CHECK_FUNCS([ntohl htonl ntohs htons])

# Define uint*_t and u_int*_t if not defined on target platform
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T


# build IP/ROHC client
AC_ARG_ENABLE(client,
              AS_HELP_STRING([--enable-client],
                             [enable IP/ROHC client [[default=yes]]]),
              [enable_client=$enableval],
              [enable_client=yes])
if test "x$enable_client" = "xyes" ; then
	iprohc_client=1
else
	iprohc_client=0
fi
AM_CONDITIONAL([IPROHC_CLIENT], [test x$iprohc_client = xyes])


# build IP/ROHC server
AC_ARG_ENABLE(server,
              AS_HELP_STRING([--enable-server],
                             [enable IP/ROHC server [[default=yes]]]),
              [enable_server=$enableval],
              [enable_server=yes])
if test "x$enable_server" = "xyes" ; then
	iprohc_server=1
else
	iprohc_server=0
fi
AM_CONDITIONAL([IPROHC_SERVER], [test x$iprohc_server = xyes])


# check if -Werror must be appended to CFLAGS
AC_ARG_ENABLE(fail_on_warning,
              AS_HELP_STRING([--enable-fail-on-warning],
                             [build fails on warnings if enabled [[default=no]]]),
              fail_on_warning=$enableval,
              fail_on_warning=no)
if test "x$fail_on_warning" != "xno"; then
	configure_cflags="${configure_cflags} -Werror -Wno-error=deprecated-declarations"
fi


# check if -D_FORTIFY_SOURCE=2 must be appended to CFLAGS
AC_ARG_ENABLE(fortify_sources,
              AS_HELP_STRING([--enable-fortify-sources],
                             [build uses -D_FORTIFY_SOURCE=2 if enabled [[default=no]]]),
              fortify_sources=$enableval,
              fortify_sources=no)
if test "x$fortify_sources" != "xno"; then
	configure_cflags="${configure_cflags} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"
fi


# check for GnuTLS presence through pkg-config
PKG_CHECK_MODULES([GNUTLS], [gnutls],
                  [gnutls_found="yes"], [gnutls_found="no"])
if test "x$gnutls_found" != "xyes" ; then
	echo
	echo "ERROR: GnuTLS library/headers not found"
	echo
	echo "Go get it from http://www.gnutls.org/ or use the GNUTLS_* variables, "
	echo "if you have it installed in unusual place. Also check if it depends "
	echo "on another shared library that may be installed in an unusual place."
	echo
	exit 1
fi
configure_cflags="$configure_cflags $GNUTLS_CFLAGS"
configure_ldflags="$configure_ldflags $GNUTLS_LIBS"


# check for librohc presence through pkg-config
PKG_CHECK_MODULES([ROHC], [rohc >= 1.7.0],
                  [librohc_found="yes"], [librohc_found="no"])
if test "x$librohc_found" != "xyes" ; then
	echo
	echo "ERROR: ROHC library/headers not found"
	echo
	echo "Go get the ROHC library from http://rohc-lib.org/ or use the ROHC_* "
	echo "variables, if you have it installed in unusual place. Also check if "
	echo "it depends on another shared library that may be installed in an "
	echo "unusual place."
	echo
	exit 1
fi
configure_cflags="$configure_cflags $ROHC_CFLAGS"
configure_ldflags="$configure_ldflags $ROHC_LIBS"


# check for libyaml presence through pkg-config
PKG_CHECK_MODULES([YAML], [yaml-0.1],
                  [libyaml_found="yes"], [libyaml_found="no"])
if test "x$iprohc_server" != "x0" && \
   test "x$libyaml_found" != "xyes" ; then
	echo
	echo "ERROR: libyaml library/headers not found"
	echo
	echo "Go get it from http://pyyaml.org/wiki/LibYAML or use the YAML_* "
	echo "variables, if you have it installed in unusual place. Also check "
	echo "if it depends on another shared library that may be installed in "
	echo "an unusual place."
	echo
	exit 1
fi
configure_cflags="$configure_cflags $YAML_CFLAGS"
configure_ldflags="$configure_ldflags $YAML_LIBS"


# check for libtimerfd presence through pkg-config
PKG_CHECK_MODULES([TIMERFD], [timerfd],
                  [libtimerfd_found="yes"], [libtimerfd_found="no"])
if test "x$libtimerfd_found" != "xyes" ; then
	# timerfd API provided by libc
	:
else
	# timerfd API provided by the libtimerfd library
	configure_cflags="$configure_cflags $TIMERFD_CFLAGS"
	configure_ldflags="$configure_ldflags $TIMERFD_LIBS"
fi


# libnetlink.h is required
AC_CHECK_HEADERS([libnetlink.h], [], [], [[#include <sys/socket.h>
#include <stdio.h>]])
if test "x$ac_cv_header_libnetlink_h" != "xyes" ; then
	echo
	echo "ERROR: libnetlink.h header not found"
	echo
	echo "Please install iproute2 and its header files."
	echo
	exit 1
fi
# check whether rtnl_talk() takes 5 or 7 arguments
AC_MSG_CHECKING([how many arguments rtnl_talk takes])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>
                                     #include <stdlib.h>
                                     #include <sys/socket.h>
                                     #include <libnetlink.h>]],
                                   [[rtnl_talk(NULL, NULL, 0, 0, NULL);]])],
                  [rtnl_talk_params=5],
                  [rtnl_talk_params=7])
AC_MSG_RESULT([$rtnl_talk_params])
AC_DEFINE_UNQUOTED([RTNL_TALK_PARAMS],
                   [$rtnl_talk_params],
                   [Define the number of arguments that rtnl_talk takes])


# check if documentation should be generated (HTML format with doxygen)
AC_ARG_ENABLE(doc_html,
              AS_HELP_STRING([--enable-doc-html],
                             [generate documentation in HTML format [default=no]]),
              [build_doc_html=$enableval],
              [build_doc_html=no])
AM_CONDITIONAL([BUILD_DOC_HTML], [test "x$build_doc_html" = "xyes"])

# doxygen is mandatory if HTML documentation generation is enabled
if test "x$build_doc_html" = "xyes" ; then
	# check for the doxygen binary and abort if it is not found
	AC_CHECK_PROG(is_doxygen_found, doxygen, "yes", "no")
	if test "x$is_doxygen_found" != "xyes"; then
		echo
		echo "ERROR: doxygen binary not found"
		echo
		echo "doxygen is required in order to generate the HTML documentation."
		echo
		echo "Go get it from http://www.doxygen.org/ or use your package manager "
		echo "to install it on your system."
		echo
		exit 1
	fi
fi


# check if API documentation should be generated (man format with doxygen
# and a modified version of doxy2man)
AC_ARG_ENABLE(doc_man,
              AS_HELP_STRING([--enable-doc-man],
                             [generate documentation in man format [default=no]]),
              [build_doc_man=$enableval],
              [build_doc_man=no])
AM_CONDITIONAL([BUILD_DOC_MAN], [test "x$build_doc_man" = "xyes"])

# help2man is mandatory if lan documentation generation is enabled
if test "x$build_doc_man" = "xyes" ; then
	# check for the help2man binary and abort if it is not found
	AC_CHECK_PROG(is_help2man_found, help2man, "yes", "no")
	if test "x$is_help2man_found" != "xyes"; then
		echo
		echo "ERROR: help2man binary not found"
		echo
		echo "help2man is required in order to generate the man pages."
		echo
		exit 1
	fi
fi


# export configure_cflags and configure_ldflags
AC_SUBST([configure_cflags], [$configure_cflags])
AC_SUBST([configure_ldflags], [$configure_ldflags])

AM_DEP_TRACK

AC_CONFIG_FILES([ \
	Makefile \
	bzr_revno \
	src/Makefile \
	src/common/Makefile \
	src/client/Makefile \
	src/server/Makefile \
	doc/Makefile \
	doc/doxygen.conf \
	contrib/Makefile \
])

AC_OUTPUT
