#!/usr/bin/env bash
# No downloads, global tuning, or root privileges. REPEAT=1 is a quick check.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
deps=${TURTLE_DEPS_ROOT:-"$root/.deps"}
build=${TURTLE_BUILD_DIR:-"$root/build"}
tests=${TURTLE_TEST_BUILD_DIR:-"$root/build-tests"}
jobs=${JOBS:-4}
repeat=${REPEAT:-20}
wolf=OFF
mbed=OFF
[[ ! -f "$deps/install/wolfssl-5.8.2-stable/include/wolfssl/ssl.h" ]] || wolf=ON
[[ ! -f "$deps/install/mbedtls-3.6.4-pic/include/mbedtls/ssl.h" ]] || mbed=ON
options=(-G Ninja -DTURTLE_WARNINGS_AS_ERRORS=ON "-DTURTLE_DEPS_ROOT=$deps"
         "-DTURTLE_WITH_WOLFSSL=$wolf" "-DTURTLE_WITH_MBEDTLS=$mbed")
printf 'Adapters: OpenSSL=ON wolfSSL=%s MbedTLS=%s\n' "$wolf" "$mbed"
cmake -S "$root" -B "$build" "${options[@]}" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build" --parallel "$jobs"
cmake -S "$root/tests" -B "$tests" "${options[@]}" -DCMAKE_BUILD_TYPE=Debug
cmake --build "$tests" --parallel "$jobs"
ctest --test-dir "$tests" --output-on-failure --repeat "until-fail:$repeat" -j "$jobs"
python3 "$root/scripts/check-modules.py" --root "$root"
for script in "$root"/scripts/*.sh; do bash -n "$script"; done
git -C "$root" diff --check
if [[ ${STATIC_CHECKS:-0} == 1 ]]; then "$root/scripts/static-check.sh" "$build"; fi
