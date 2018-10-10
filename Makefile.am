bin_PROGRAMS = esocks
noinst_PROGRAMS = testapp

ACLOCAL_AMFLAGS = -I m4

testapp_SOURCES = testapp.c \
		evs_server.c evs_server.h \
		evs_log.c evs_log.h \
		evs_helper.c evs_helper.h \
		crypto.c crypto.h \
		evs_lru.c evs_lru.h evs_relay.c

esocks_SOURCES = evs_server.c evs_server.h \
		  evs_log.c evs_log.h \
		  evs_helper.c evs_helper.h \
		  crypto.c crypto.h \
		  evs_lru.c evs_lru.h \
		  evs_relay.c daemon.c esocks.c

test: testapp
	$(srcdir)/testapp

maintainer-clean-local:
	-rm Makefile.in
	-rm aclocal.m4
	-rm config.guess
	-rm config.sub
	-rm depcomp
	-rm install-sh
	-rm ltmain.sh
	-rm missing
	-rm configure
	-rm config.log
	-rm config.status
