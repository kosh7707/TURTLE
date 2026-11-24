#!/bin/sh
# One target profile drives the benchmark. No specimen-specific build steps.
set -eu
usage() { printf 'Usage: %s [PROFILE.json [NEW_OUTPUT]] | --client APP [ARGS...] | --server APP [ARGS...]\n' "$0"; }
role=
case ${1-} in
    -h|--help) usage; exit 0;;
    --client|--server) role=${1#--}; shift; [ "$#" -ge 1 ] || { usage >&2; exit 2; };;
    *) [ "$#" -le 2 ] || { usage >&2; exit 2; };;
esac
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
build=${TURTLE_BUILD_DIR:-"$root/build"}
if [ ! -x "$build/turtle" ]; then
    # A new launcher build does not need the test suite. Respect any
    # custom adapters and test configuration in an existing build tree.
    if [ ! -f "$build/CMakeCache.txt" ]; then
        cmake -S "$root" -B "$build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
    fi
    cmake --build "$build" --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
fi
if [ -z "$role" ] && [ "$#" = 2 ]; then
    out=$2
else
    base=${TURTLE_OUTPUT_DIR:-"$root/outputs"}
    mkdir -p "$base"
    reservation=$(umask 077; mktemp -d "$base/run-XXXXXXXX")
    out=$reservation.results
    rmdir "$reservation"
fi
printf 'Outputs: %s\n' "$out"
if [ -n "$role" ]; then exec "$build/turtle" target "$role" "$out" "$@"; fi
if [ "$#" = 0 ]; then exec "$build/turtle-pair" "$out"; fi
exec "$build/turtle" run "$1" "$out"
