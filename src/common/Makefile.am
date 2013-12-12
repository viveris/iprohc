################################################################################
# Name       : Makefile
# Authors    : Didier Barvaux <didier@barvaux.org>
# Description: create the IP/ROHC common internal library
################################################################################


noinst_LTLIBRARIES = libiprohc_common.la

libiprohc_common_la_SOURCES = \
	rohc_tunnel.c \
	tlv.c \
	tun_helpers.c \
	session.c

libiprohc_common_la_LIBADD = \
	-lgnutls \
	-lrohc \
	-lnetlink

libiprohc_common_la_LDFLAGS = \
	$(configure_ldflags)

libiprohc_common_la_CFLAGS = \
	$(configure_cflags)

libiprohc_common_la_CPPFLAGS =

noinst_HEADERS = \
	ip_chksum.h \
	log.h \
	rohc_tunnel.h \
	tlv.h \
	tun_helpers.h \
	session.h \
	utils.h

