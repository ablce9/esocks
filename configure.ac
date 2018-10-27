AC_PREREQ([2.69])
AC_INIT([esocks], [ESOCKS_VERSION], [shunsuketamiya@posteo.net])
AC_CANONICAL_HOST
AC_CONFIG_SRCDIR([server.c])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
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

LIBS="-ldl"

if test "x$enable_static" = "xyes"; then
   CFLAGS="-static $CFLAGS"
   LIBS="-pthread $LIBS"
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

trylibeventdir=""
AC_ARG_WITH(libevent,
       [  --with-libevent=PATH     Specify path to libevent installation ],
       [
		if test "x$withval" != "xno" ; then
			trylibeventdir=$withval
		fi
       ]
)

dnl ------------------------------------------------------
dnl libevent detection.  swiped from Tor and Memcached.

LIBEVENT_URL=http://www.monkey.org/~provos/libevent/

AC_CACHE_CHECK([for libevent directory], ac_cv_libevent_dir, [
  saved_LIBS="$LIBS"
  saved_LDFLAGS="$LDFLAGS"
  saved_CPPFLAGS="$CPPFLAGS"
  le_found=no
  for ledir in $trylibeventdir "" $prefix /usr/local ; do
    LDFLAGS="$saved_LDFLAGS"
    LIBS="-levent $saved_LIBS"

    # Skip the directory if it isn't there.
    if test ! -z "$ledir" -a ! -d "$ledir" ; then
       continue;
    fi
    if test ! -z "$ledir" ; then
      if test -d "$ledir/lib" ; then
	LDFLAGS="-L$ledir/lib $LDFLAGS"
      else
	LDFLAGS="-L$ledir $LDFLAGS"
      fi
      if test -d "$ledir/include" ; then
	CPPFLAGS="-I$ledir/include $CPPFLAGS"
      else
	CPPFLAGS="-I$ledir $CPPFLAGS"
      fi
    fi
    # Can I compile and link it?
    AC_TRY_LINK([#include <sys/time.h>
#include <sys/types.h>
#include <event.h>], [ event_init(); ],
       [ libevent_linked=yes ], [ libevent_linked=no ])
    if test $libevent_linked = yes; then
       if test ! -z "$ledir" ; then
	 ac_cv_libevent_dir=$ledir
	 _myos=`echo $target_os | cut -f 1 -d .`
	 AS_IF(test "$SUNCC" = "yes" -o "x$_myos" = "xsolaris2",
	       [saved_LDFLAGS="$saved_LDFLAGS -Wl,-R$ledir/lib"],
	       [AS_IF(test "$GCC" = "yes",
		     [saved_LDFLAGS="$saved_LDFLAGS -Wl,-rpath,$ledir/lib"])])
       else
	 ac_cv_libevent_dir="(system)"
       fi
       le_found=yes
       break
    fi
  done
  LIBS="$saved_LIBS"
  LDFLAGS="$saved_LDFLAGS"
  CPPFLAGS="$saved_CPPFLAGS"
  if test $le_found = no ; then
    AC_MSG_ERROR([libevent is required.  You can get it from $LIBEVENT_URL

      If it's already installed, specify its path using --with-libevent=/dir/
])
  fi
])
LIBS="-levent $LIBS"
if test $ac_cv_libevent_dir != "(system)"; then
  if test -d "$ac_cv_libevent_dir/lib" ; then
    LDFLAGS="-L$ac_cv_libevent_dir/lib $LDFLAGS"
    le_libdir="$ac_cv_libevent_dir/lib"
  else
    LDFLAGS="-L$ac_cv_libevent_dir $LDFLAGS"
    le_libdir="$ac_cv_libevent_dir"
  fi
  if test -d "$ac_cv_libevent_dir/include" ; then
    CPPFLAGS="-I$ac_cv_libevent_dir/include $CPPFLAGS"
  else
    CPPFLAGS="-I$ac_cv_libevent_dir $CPPFLAGS"
  fi
fi

tryopenssl=""
AC_ARG_WITH(openssl,
	[ --with-openssl=PATH Specify a path to openssl],
	[
		if test "x$xwithval" != "xno"; then
		   tryopenssl=$withval
		fi
	]
)

dnl Checks for OpenSSL.
AC_CACHE_CHECK(
	[for openssl],
	[ac_cv_openssl],
	[
	CPPFLAGS="-I$tryopenssl/include $CPPFLAGS"
	LDFLAGS="-L$tryopenssl/lib $LDFLAGS"
	LIBS="-lcrypto $LIBS"
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
			[[
			#include <openssl/evp.h>
			#include <openssl/err.h>
			]],
			[[
			OPENSSL_malloc_init();
			ERR_load_crypto_strings();
			OpenSSL_add_all_algorithms();
			]],
		)],
		[ac_cv_openssl=yes],
		[ac_cv_openssl=no]
	)]
	if test $ac_cv_openssl = no; then
	   AC_MSG_ERROR([You have wrong version of OpenSSL.
	   ])
	fi
)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
