################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the internal HTML documentation for the IP/ROHC application
################################################################################

htmldir = $(docdir)/html


html_DATA = \
	html/*.html \
	html/*.map \
	html/*.css \
	html/*.png

iprohc_all_sources = \
	$(top_srcdir)/src/common/*.c \
	$(top_srcdir)/src/common/*.h \
	$(top_srcdir)/src/client/*.c \
	$(top_srcdir)/src/client/*.h \
	$(top_srcdir)/src/server/*.c \
	$(top_srcdir)/src/server/*.h

doxygen: $(iprohc_all_sources)
	$(AM_V_GEN)doxygen doxygen.conf
	@touch doxygen


html/*.html: $(iprohc_all_sources) | doxygen
html/*.map: $(iprohc_all_sources) | doxygen
html/*.css: $(iprohc_all_sources) | doxygen
html/*.png: $(iprohc_all_sources) | doxygen


clean-local:
	-$(RM) doxygen
	-$(RM) -r html/


# extra files for releases
EXTRA_DIST = \
	doxygen.conf

