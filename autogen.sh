#!/bin/sh

ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOHEADER=${AUTOHEADER:-autoheader}
AUTOMAKE=${AUTOMAKE:-automake}

echo "+aclocal"
$ACLOCAL || exit 1

echo "+autoheader"
$AUTOHEADER || exit 1

version=0.0.0
if [ ! -z "$(git describe)" ]; then
	version="$(git describe)"
fi
echo "#define ESOCKS_VERSION \"$version\"" > evs_version.h

echo "+automake"
$AUTOMAKE --foreign --add-missing || exit 1

echo "+autoconf"
$AUTOCONF || exit 1
