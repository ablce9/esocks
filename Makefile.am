bin_PROGRAMS = esocks
noinst_PROGRAMS = testapp

ACLOCAL_AMFLAGS = -I m4

testapp_SOURCES = testapp.c \
		server.c server.h \
		log.c log.h \
		helper.c helper.h \
		crypto.c crypto.h \
		lru.c lru.h relay.c

esocks_SOURCES = server.c server.h \
		  log.c log.h \
		  helper.c helper.h \
		  crypto.c crypto.h \
		  lru.c lru.h \
		  relay.c daemon.c esocks.c

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
