#!/bin/sh
# Check the real default all products and installed SDK, not target names alone.
# Usage: tests/independence-contract.sh CLEAN_RELEASE_BUILD
set -eu
export LC_ALL=C
build=$(cd "${1:?supply a clean, built default peer-on Ninja tree with BUILD_TESTING=OFF}" && pwd)
root=$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$build/CMakeCache.txt")
grep -qx 'BUILD_TESTING:BOOL=OFF' "$build/CMakeCache.txt"
grep -qx 'TURTLE_BUILD_REFERENCE:BOOL=ON' "$build/CMakeCache.txt"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failed=0
reject() { printf 'FAIL: %s\n' "$*" >&2; failed=1; }
cmake --install "$build" --prefix "$work/sdk" >"$work/install.log"
test -x "$work/sdk/bin/turtle"
peer="$work/sdk/bin/turtle-reference"
test -x "$peer"
"$work/sdk/bin/turtle-issue-test-leaves.sh" "$work/pki" >"$work/pki.log" 2>&1
for role in client server; do
    TURTLE_CA="$work/pki/ca.crt" TURTLE_CERT="$work/pki/$role.crt" TURTLE_KEY="$work/pki/$role.key" \
        "$peer" --role "$role" --auth mtls --check >"$work/check"
    jq -e '.ready == true' "$work/check" >/dev/null
done
echo 'PASS: installed reference accepts valid client and server configurations'

# Include uninstalled default products. Inspect imported and defined symbols,
# including static executables (a renamed DUT must still fail).
find "$build" "$work/sdk/bin" -name CMakeFiles -prune -o -type f -perm /111 -print >"$work/files"
while IFS= read -r f; do
    case "$f" in "$peer"|"$build/turtle-reference") continue;; esac
    readelf -h "$f" >/dev/null 2>&1 || continue
    readelf -d "$f" >"$work/dyn"
    nm -g "$f" >"$work/syms" 2>/dev/null
    if grep -Eq 'NEEDED.*lib(ssl|wolfssl|gnutls|mbedtls)\.so' "$work/dyn" ||
       grep -Eq '[[:space:]](SSL_|wolfSSL_|gnutls_|mbedtls_ssl_)(do_handshake|handshake|connect|accept|read(_ex)?|write(_ex)?)(@|$)' "$work/syms"; then
        reject "non-peer product links a native TLS implementation: ${f#"$build"/}"
    fi
done <"$work/files"

# A consumer must no longer be able to compile either legacy dispatch style.
# Also check archives, so removing a header while exporting its entrypoint fails.
cc -x c -fsyntax-only - </dev/null
for contract in implementation role; do
    if [ "$contract" = implementation ]; then
        probe='void probe(turtle_implementation *a) { (void)a->handshake(0); }'
    else
        probe='int probe(turtle_session *s) { turtle_action a; return turtle_pull(s, &a); }'
    fi
    if printf '#include <turtle/%s.h>\n%s\n' "$contract" "$probe" |
       cc -std=c11 -Werror -I"$work/sdk/include" -x c -fsyntax-only - 2>"$work/cc.log"; then
        reject "installed consumer can dispatch native $contract operations"
    fi
done
find "$work/sdk" -type f -name '*.a' -exec nm -g --defined-only {} + >"$work/exports"
find "$work/sdk" -type f \( -name '*.so' -o -name '*.so.*' \) -exec nm -D --defined-only {} + >>"$work/exports"
test -f "$work/sdk/include/turtle/start.h"
if ! grep -Eq ' [T] turtle_wait_start(@[^ ]*)?$' "$work/exports"; then
    reject 'installed SDK missing the optional non-TLS START rendezvous'
fi
if grep -Eq ' [TW] (turtle_pull|turtle_submit|turtle_endpoint_main)(@[^ ]*)?$' "$work/exports"; then
    reject 'installed SDK exports a legacy native-operation dispatcher'
fi

# Check source-only stubs too: do not make a developer copy a TLS-operation
# translator from examples, fixtures or a disabled implementation directory.
# Exempt only files in the actual dependency closure of the allowed peer.
ninja -C "$build" -t inputs turtle-reference >"$work/reference-inputs"
for dir in examples implementations tests; do
    [ -d "$root/$dir" ] || continue
    find "$root/$dir" -type f \( -name '*.c' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) -print
done >"$work/sources"
while IFS= read -r f; do
    grep -Fxq "$f" "$work/reference-inputs" && continue
    if grep -Eq '(SSL_do_handshake|wolfSSL_(connect|accept)|gnutls_handshake|mbedtls_ssl_handshake)[[:space:]]*\(' "$f" &&
       grep -Eq 'TURTLE_(HS|FIRST_HS|AGAIN_READ|WANT_READ)|turtle_(implementation|pull|submit)' "$f"; then
        reject "shipped non-peer source translates native TLS operations: ${f#"$root"/}"
    fi
done <"$work/sources"
[ "$failed" = 0 ] && echo 'PASS: no bundled DUT, installed operation dispatcher or non-peer native TLS stub'
exit "$failed"
