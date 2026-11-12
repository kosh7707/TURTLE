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
bithac=OFF
mlkem=OFF
[[ ! -f "$deps/install/wolfssl-5.8.2-stable/include/wolfssl/ssl.h" ]] || wolf=ON
[[ ! -f "$deps/install/mbedtls-3.6.4-pic/include/mbedtls/ssl.h" ]] || mbed=ON
if [[ -f "$deps/install/bithac-baseline/lib/libwolfssl.a" && -f "$deps/install/bithac-cached/lib/libwolfssl.a" ]]; then bithac=ON; fi
if [[ -f "$deps/install/mlkem-c/lib/libwolfssl.a" && -f "$deps/install/mlkem-avx2/lib/libwolfssl.a" ]]; then mlkem=ON; fi
options=(-G Ninja -DTURTLE_BUILD_LOOKUP=ON -DTURTLE_ADAPTER_LINKAGE=module -DTURTLE_BUILD_MODULES=ON -DTURTLE_WITH_OPENSSL=ON -DTURTLE_WARNINGS_AS_ERRORS=ON "-DTURTLE_DEPS_ROOT=$deps"
         "-DTURTLE_WITH_WOLFSSL=$wolf" "-DTURTLE_WITH_MBEDTLS=$mbed" "-DTURTLE_WITH_BITHAC=$bithac"
         "-DTURTLE_WITH_MLKEM=$mlkem")
printf 'Adapters: OpenSSL=ON wolfSSL=%s MbedTLS=%s BiTHaC=%s ML-KEM=%s\n' "$wolf" "$mbed" "$bithac" "$mlkem"
cmake -S "$root" -B "$build" "${options[@]}" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build" --parallel "$jobs"
cmake -S "$root/tests" -B "$tests" "${options[@]}" -DCMAKE_BUILD_TYPE=Debug
cmake --build "$tests" --parallel "$jobs"
ctest --test-dir "$tests" --output-on-failure --repeat "until-fail:$repeat" -j "$jobs"
python3 "$root/scripts/check-modules.py" --root "$root"
for script in "$root"/scripts/*.sh; do bash -n "$script"; done
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "$root" diff --check
else
    printf 'Git metadata absent; diff check unavailable for this source snapshot.\n'
fi
if [[ ${STATIC_CHECKS:-0} == 1 ]]; then "$root/scripts/static-check.sh" "$build"; fi
