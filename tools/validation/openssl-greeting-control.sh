#!/bin/sh
# OpenSSL-only diagnostic, never a normal timing sample.
set -eu
umask 077
if [ "$#" -ne 3 ]; then
    printf 'usage: %s FRAMEWORK_DIR BUILD_ONLY_JOB NEW_OUTPUT\n' "$0" >&2
    exit 2
fi
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
framework=$(realpath -e "$1")
build=$(realpath -e "$2/build")
mkdir -- "$3"
out=$(realpath -e "$3")
prefix="$build/prefix"
object=$(sed -n 's/^object=//p' "$build/link-evidence.txt")
test -f "$object"
for side in client server; do
    grep -Fx "LOAD $object" "$build/$side.map" >"$out/$side-bridge-object.log"
done
unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH LD_DEBUG LD_DEBUG_OUTPUT TURTLE_PMU TURTLE_EVIDENCE_FD
sha256sum -c "$build/expected-libs.sha256" >"$out/private-libraries.log"
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Wpedantic -Werror \
    -I"$root/src/include" -I"$prefix/include" \
    "$root/tools/validation/openssl-greeting-control.cpp" "$object" \
    "$prefix/lib/libssl.so" "$prefix/lib/libcrypto.so" "$framework/libturtle_observe.so" \
    -Wl,--disable-new-dtags "-Wl,-rpath,$prefix/lib:$framework" -o "$out/cf-control"
ldd "$out/cf-control" >"$out/loader.log"
while IFS= read -r library; do
    grep -F "=> $library " "$out/loader.log" >/dev/null
done < "$build/expected-libs.txt"
sha256sum "$object" "$out/cf-control" >"$out/control-identities.sha256"
keys=$(mktemp -d)
trap 'rm -rf -- "$keys"' EXIT
sh "$framework/turtle-issue-test-leaves.sh" "$keys/leaf" >"$out/issuance.log" 2>&1
cp "$keys/leaf/"*.crt "$out"
for auth in server mtls; do
    rc=0
    timeout 20 "$out/cf-control" "$keys/leaf" "$auth" >"$out/$auth.log" 2>&1 || rc=$?
    printf '%s\n' "$rc" >"$out/$auth.exit"
    [ "$rc" -eq 0 ]
    grep -F 'client: validated SAD1 before CF release:' "$out/$auth.log" >/dev/null
    grep -Fx 'server: submitted accept(greeting) completed' "$out/$auth.log" >/dev/null
done
sha256sum -c "$build/expected-libs.sha256" >>"$out/private-libraries.log"
printf 'Verified full SAD1 receipt while CF record withheld, both auth modes: %s\n' "$out"
