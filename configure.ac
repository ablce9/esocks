AC_PREREQ([2.69])
AC_INIT([esocks], [0.0.0], [shunsuketamiya@posteo.net])
AC_CANONICAL_HOST
AC_CONFIG_SRCDIR([evs_server.c])
AM_INIT_AUTOMAKE([foreign])
AM_CONFIG_HEADER([config.h])

AC_PROG_CC

dnl Initialize prefix
if ! test -z "$prefix"; then
   prefix=/usr/local
fi

dnl If possible, enable extensions to C or Posix on hosts that disable the extensions.
dnl Autocnf version > 2.60
AC_USE_SYSTEM_EXTENSIONS

dnl Checks for programs.
dnl A macro for GNU Make to choose the default C compilation rule.
AC_PROG_CC_C_O
# Not yet
# AC_PROG_INSTALL
dnl Configure `ln -s`, if works. Otherwise set it to `cp -p.
AC_PROG_LN_S

if test "$GCC" = "yes"; then
   # Include all gcc warnings
   CFLAGS="$CFLAGS -Wall"
fi

AC_ARG_ENABLE(gcc-warnings,
	AS_HELP_STRING([--disable-gcc-warnings],[disable all warnings with GCC]))

AC_ARG_ENABLE(gcc-hardening,
     AS_HELP_STRING(--enable-gcc-hardening, enable compiler security checks),
[if test x$enableval = xyes; then
    CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2 -fstack-protector-all"
    CFLAGS="$CFLAGS -fwrapv -fPIE -Wstack-protector"
    CFLAGS="$CFLAGS --param ssp-buffer-size=1"
fi])

AC_ARG_ENABLE(debug,
	[AS_HELP_STRING([--enable-debug],[build debug mode])])

if test "x$enable_debug" = "xyes"; then
   old_cflags=$CFLAGS
   CFLAGS="-DDEBUG=1 -g -ggdb -O3"
fi

AC_ARG_ENABLE(64bit,
	[AS_HELP_STRING([--enable-64bit],[build 64-bit version])])
if test "x$enable_64bit" = "xyes"; then
   CFLAGS="-m64 $CFLAGS"
fi

AC_ARG_ENABLE(static,
	[AS_HELP_STRING([--enable-static],[build static binary])])

if test "x$enable_static" = "xyes"; then
   CFLAGS="-static $CFLAGS"
fi

dnl Checks for header files.
AC_CHECK_HEADERS([ \
  errno.h \
  getopt.h \
  fcntl.h \
  netdb.h \
  netinet/in.h \
  netinet/in6.h \
  netinet/tcp.h \
])

dnl Search for network library to handle static linking
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)

dnl Checks for library functions.
AC_CHECK_FUNCS([accept4], [AC_DEFINE(HAVE_ACCEPT4, 1, [Define to 1 if support accept4])])

AC_CACHE_CHECK(
	[for getaddrinfo],
	[ac_cv_getaddrinfo],
	[AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[[
			#ifdef HAVE_NETDB_H
			#include <netdb.h>
			#endif
			]],
			[[
			getaddrinfo;
			]]
		)],
		[ac_cv_getaddrinfo=yes],
		[ac_cv_getaddrinfo=no]
	)]
)

if test "$ac_cv_getaddrinfo" = "$xyes"; then
   AC_DEFINE([HAVE_GETADDRINFO], 1, [Define to 1 if support getaddrinfo])
fi

dnl Checks for TCP_FASTOPEN and TCP_NODELAY.
AC_CACHE_CHECK(
	[for sol_tcp],
	[ac_cv_sol_tcp],
	[AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[[
			#ifdef HAVE_NETINET_TCP_H
			#include <netinet/tcp.h>
			#endif
			#include <sys/socket.h>
			#include <sys/types.h>
			]],
			[[
			int fd, optval=5;
			fd=socket(AF_INET,SOCK_STREAM,0);
			setsockopt(fd,SOL_TCP,TCP_FASTOPEN,(void*)&optval, sizeof(optval));
			setsockopt(fd,SOL_TCP,TCP_NODELAY,(void*)&optval, sizeof(optval));
			]]
		)],
		[ac_cv_sol_tcp=yes],
		[ac_cv_sol_tcp=no]
	)]
)

if test "$ac_cv_sol_tcp" = "yes"; then
   AC_DEFINE([HAVE_TCP_FASTOPEN], 1, [Define to 1 if support tcp fastopen])
   AC_DEFINE([HAVE_TCP_NODELAY], 1, [Define to 1 if support tcp nodelay])
fi

LIBS="-ldl"

pathtolibevent=""
AC_ARG_WITH(libevent,
	[ --with-libevent=PATH Specify a path to libevent],
	[
		if test "x$xwithval" != "xno"; then
		   pathtolibevent=$withval
		fi
	]
)

dnl Checks for libevent
AC_CACHE_CHECK(
	[for libevent],
	[ac_cv_libevent],
	[
	if ! test -z "$pathtolibevent"; then
	   LDFLAGS="-L$$pathtolibevent $LDFLAGS"
	else
	   LDFLAGS="-L/usr/local/lib $LDFLAGS"
	fi
	LIBS="-levent $LIBS"
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[[
			#include <sys/time.h>
			#include <sys/types.h>
			#include <event.h>
			]],
			[[
			event_init();
			]]
		)],
		[ac_cv_libevent=yes],
		[ac_cv_libevent=no]
	)]
)

if ! test "$ac_cv_libevent" = "yes"; then
   AC_MSG_ERROR([Libevent is not installed. You can get it from http://libevent.org/.])
fi

pathtoopenssl=""
AC_ARG_WITH(libevent,
	[ --with-libevent=PATH Specify a path to openssl],
	[
		if test "x$xwithval" != "xno"; then
		   pathtoopenssl=$withval
		fi
	]
)

dnl Checks for OpenSSL.
AC_CACHE_CHECK(
	[for openssl],
	[ac_cv_openssl],
	[
	LIBS="-lcrypto $LIBS"
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[[
			#include <openssl/evp.h>
			]],
			[[
			OpenSSL_add_all_algorithms();
			]],
		)],
		[ac_cv_openssl=yes],
		[ac_cv_openssl=no]
	)]
)
if ! test "$ac_cv_libevent" = "yes"; then
	AC_MSG_ERROR([OpenSSL is not installed. You should get it from wherever OpenSSL is hosted.])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
