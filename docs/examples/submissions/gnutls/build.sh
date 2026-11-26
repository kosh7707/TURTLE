#!/bin/sh
set -eu
fail() { printf '%s\n' "$*" >&2; exit 2; }
[ "$#" -ge 2 ] || fail "usage: build.sh ABS_WORK ABS_PREFIX [configure feature options...]"
case $1 in /*) work=$1;; *) fail "WORK must be absolute";; esac
case $2 in /*) prefix=$2;; *) fail "PREFIX must be absolute";; esac
shift 2
jobs=${JOBS:-4}
case $jobs in ''|*[!0-9]*) fail "JOBS must be a positive integer";; esac
[ "$jobs" -gt 0 ] || fail "JOBS must be a positive integer"
for option do
    case $option in
        --disable-shared|--disable-shared=*|--enable-shared=*)
            fail "build.sh requires shared libraries: $option";;
        --enable-*|--disable-*|--with-*|--without-*|CC=*|CFLAGS=*|CPPFLAGS=*|CXX=*|CXXFLAGS=*|LDFLAGS=*|LIBS=*) ;;
        *) fail "pass configure feature options, not work or install overrides: $option";;
    esac
done
src=$(CDPATH='' cd -- ./gnutls && pwd -P)
cd "$work"
"$src/configure" \
    --enable-shared --disable-static --disable-doc --disable-tools --disable-tests \
    --disable-full-test-suite --disable-cxx --disable-nls --with-included-unistring "$@" \
    --prefix="$prefix" --libdir="$prefix/lib"
make -j"$jobs"
make DESTDIR= install
