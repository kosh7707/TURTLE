#!/bin/sh
set -eu
fail() { printf '%s\n' "$*" >&2; exit 2; }
[ "$#" -ge 2 ] || fail "usage: build.sh ABS_WORK ABS_PREFIX [-DNAME=VALUE ...]"
case $1 in /*) work=$1;; *) fail "WORK must be absolute";; esac
case $2 in /*) prefix=$2;; *) fail "PREFIX must be absolute";; esac
shift 2
jobs=${JOBS:-4}
case $jobs in ''|*[!0-9]*) fail "JOBS must be a positive integer";; esac
[ "$jobs" -gt 0 ] || fail "JOBS must be a positive integer"
for option do
    case $option in
        -DCMAKE_INSTALL_*=*|-DCMAKE_STAGING_PREFIX=*|-DCMAKE_STAGING_PREFIX:*=*|-DBUILD_SHARED_LIBS=*|-DBUILD_SHARED_LIBS:*=*)
            fail "build.sh owns the private install paths and requires shared libraries: $option";;
        -D?*=*) ;;
        *) fail "pass CMake settings as single -DNAME=VALUE arguments: $option";;
    esac
done
src=$(CDPATH='' cd -- ./wolfssl && pwd -P)
cmake -S "$src" -B "$work" \
    -DBUILD_SHARED_LIBS=ON -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no \
    "$@" "-DCMAKE_INSTALL_PREFIX=$prefix"
cmake --build "$work" --parallel "$jobs"
DESTDIR= cmake --install "$work"
