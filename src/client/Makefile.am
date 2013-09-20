################################################################################
# Name       : Makefile
# Author     : Didier Barvaux <didier@barvaux.org>
# Description: create the IP/ROHC client
################################################################################

sbin_PROGRAMS = iprohc_client

if BUILD_DOC_MAN
man_MANS = iprohc_client.1
endif


iprohc_client_CFLAGS = \
	$(configure_cflags)

iprohc_client_CPPFLAGS = \
	-I$(top_srcdir)/ \
	-I$(top_srcdir)/src/common

iprohc_client_LDFLAGS = \
	$(configure_ldflags) \
	-L$(top_builddir)/src/common/.libs

iprohc_client_SOURCES = \
	client.c \
	messages.c \
	tls.c

iprohc_client_LDADD = \
	-liprohc_common

noinst_HEADERS = \
	messages.h \
	tls.h

iprohc_client.1: $(iprohc_client_SOURCES)
	$(AM_V_GEN)help2man --output=$@ -s 1 --no-info \
		-m "$(PACKAGE_NAME)'s tools" -S "$(PACKAGE_NAME)" \
		--help-option=help --version-option=version \
		-n "The IP/ROHC client" \
		$(builddir)/iprohc_client

