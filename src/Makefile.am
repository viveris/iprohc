################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier@barvaux.org>
#	Description: create the IP/ROHC client and server
################################################################################

if BUILD_CLIENT
CLIENT_DIR = client
else
CLIENT_DIR =
endif

if BUILD_SERVER
SERVER_DIR = server
else
SERVER_DIR =
endif

SUBDIRS = \
	common \
	$(CLIENT_DIR) \
	$(SERVER_DIR)

