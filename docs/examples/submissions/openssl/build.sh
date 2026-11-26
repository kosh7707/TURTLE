#!/bin/sh
set -eu
fail() { printf '%s\n' "$*" >&2; exit 2; }
[ "$#" -ge 2 ] || fail "usage: build.sh ABS_WORK ABS_PREFIX [OpenSSL Configure options...]"
case $1 in /*) work=$1;; *) fail "WORK must be absolute";; esac
case $2 in /*) prefix=$2;; *) fail "PREFIX must be absolute";; esac
shift 2
jobs=${JOBS:-4}
case $jobs in ''|*[!0-9]*) fail "JOBS must be a positive integer";; esac
[ "$jobs" -gt 0 ] || fail "JOBS must be a positive integer"
for option do
    case $option in
        --prefix|--prefix=*|--libdir|--libdir=*|--openssldir|--openssldir=*|\
        -no-shared|no-shared|disable-shared|-no-pic|no-pic|disable-pic)
            fail "build.sh owns the private install paths and requires shared libraries: $option";;
    esac
done
src=$(CDPATH='' cd -- ./openssl && pwd -P)
cd "$work"
"$src/Configure" shared no-tests "$@" --prefix="$prefix" --libdir=lib --openssldir="$prefix/ssl"
make -j"$jobs" build_sw
make DESTDIR= install_sw install_ssldirs
