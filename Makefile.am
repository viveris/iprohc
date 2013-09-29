################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the IP/ROHC application
################################################################################

if BUILD_DOC_HTML
DOC_DIR = doc
else
DOC_DIR =
endif

SUBDIRS = \
	src \
	$(DOC_DIR) \
	contrib

dist_doc_DATA = \
	README \
	INSTALL \
	COPYING \
	AUTHORS \
	ChangeLog

# directory for dist and distcheck
distdir = $(PACKAGE)-$(VERSION)$(PACKAGE_REVNO)

# configure options for distcheck
DISTCHECK_CONFIGURE_FLAGS = \
	--enable-fail-on-warning \
	--enable-fortify-sources \
	--disable-doc-html \
	--disable-doc-man

# extra files for releases
EXTRA_DIST = \
	autogen.sh \
	bzr_revno

