#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
build=${TURTLE_BUILD_DIR:-"$root/build-message"}
deps=${TURTLE_DEPS_ROOT:-"$root/.deps-message"}
implementations=${1:-'openssl;mbedtls;wolfssl;mlkem;bithac;openssl-padded'}
cmake -S "$root" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DTURTLE_DEPS_ROOT="$deps" -DTURTLE_IMPLEMENTATIONS="$implementations"
cmake --build "$build" -j "${JOBS:-4}"
python3 "$root/scripts/provenance.py" "$build" "$deps"
