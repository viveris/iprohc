################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier@barvaux.org>
# Description: create the IP/ROHC server
################################################################################

sbin_PROGRAMS = iprohc_server

if BUILD_DOC_MAN
man_MANS = iprohc_server.1
endif


iprohc_server_CFLAGS = \
	$(configure_cflags)

iprohc_server_CPPFLAGS = \
	-I$(top_srcdir)/ \
	-I$(top_srcdir)/src/common

iprohc_server_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs

iprohc_server_SOURCES = \
	client.c \
	server_config.c \
	messages.c \
	server.c \
	tls.c

iprohc_server_LDADD = \
	-liprohc_common \
	-lyaml \
	-lm

noinst_HEADERS = \
	client.h \
	messages.h \
	server_config.h \
	server.h \
	tls.h

iprohc_server.1: $(iprohc_server_SOURCES) $(builddir)/iprohc_server
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		-n "The IP/ROHC server" \
		$(builddir)/iprohc_server


