#!/bin/sh
# Starter recipe. TURTLE calls this from implementations/, not from WORK.
set -eu
if [ "$#" -lt 2 ]; then
    echo 'Usage: build.sh WORK PREFIX [native build arguments...]' >&2
    exit 2
fi
work=$1 prefix=$2
shift 2

# Implement your library's out-of-tree build here. Use "$work" for temporary
# files, install the headers, shared library and pkg-config metadata in "$prefix",
# and forward "$@" unchanged. Do not compile implementation.cpp here.
printf 'Starter only: no TLS SDK was built in %s or installed in %s.\n' "$work" "$prefix" >&2
echo 'Edit implementations/build.sh or see docs/submission.md.' >&2
exit 2
