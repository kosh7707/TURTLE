#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
if [ -n "${1-}" ]; then export CMAKE_PREFIX_PATH="$1${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"; fi
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
t=$tmp/TURTLE
slot=$t/implementations
mkdir -p "$slot" "$t/docs"
cp "$root/CMakeLists.txt" "$root/bench.sh" "$t/"
cp -R "$root/src" "$root/tools" "$t/"
cp -R "$root/docs/examples" "$t/docs/"
if [ -d "$root/.deps" ]; then ln -s "$root/.deps" "$t/.deps"; fi
export TURTLE_BUILD_DIR="$tmp/framework"
unset TURTLE_USE_MODULE
run() {
    rc=0
    (cd / && "$t/bench.sh" "$@") > "$tmp/run.log" 2>&1 || rc=$?
}
expect() {
    if [ "$rc" -ne "$1" ]; then cat "$tmp/run.log" >&2; exit 1; fi
}
run --build-only --out "$tmp/missing"
expect 2
grep -q 'Missing submission' "$tmp/run.log"
test ! -e "$tmp/missing"
test ! -e "$TURTLE_BUILD_DIR"

mkdir "$slot/not a catalog entry"
printf '%s\n' 'int specimen(void) { return 9; }' > "$slot/not a catalog entry/thing.c"
cat > "$slot/implementation.cpp" <<'CPP'
#include <turtle/implementation.hpp>
#include <specimen_config.h>
extern "C" int specimen(void);
struct turtle_tls { int value; };
turtle_tls *turtle_tls_setup(const turtle_tls_config *, int) {
  return new turtle_tls{specimen() + SPECIMEN_SETTING};
}
void turtle_tls_free(turtle_tls *s) { delete s; }
turtle_status turtle_tls_set_hooks(turtle_tls *, const turtle_transport_hooks *) { return TURTLE_TLS_UNSUPPORTED; }
turtle_status turtle_tls_connect(turtle_tls *) { return TURTLE_TLS_UNSUPPORTED; }
turtle_status turtle_tls_accept(turtle_tls *, const unsigned char *, size_t) { return TURTLE_TLS_UNSUPPORTED; }
ptrdiff_t turtle_app_send(turtle_tls *, const unsigned char *, size_t) { return -1; }
ptrdiff_t turtle_app_recv(turtle_tls *, unsigned char *, size_t) { return -1; }
CPP
cp "$root/tests/fixtures/submission-recipe.sh" "$slot/build.sh"
chmod +x "$slot/build.sh"
run --build-only --out "$slot/would-pollute-source"
expect 2
test ! -e "$slot/would-pollute-source"
run --build-only --repetitions 1 --out "$tmp/runtime-option"
expect 2
test ! -e "$tmp/runtime-option"

job=$tmp/job
run --build-only --out "$job" -- good 'two words' '' '*'
expect 0
b=$job/build
test "$(cat "$b/module.txt")" = unregistered
test "$(cat "$b/native.exit")" = 0
grep -Fq "$b/prefix/public/specimen_config.h" "$b/implementation.d"
obj=$(sed -n 's/^object=//p' "$b/link-evidence.txt")
for role in client server; do
    test -x "$b/bin/$role"
    grep -Fxq "LOAD $obj" "$b/$role.map"
    grep -Fxq "LOAD $b/prefix/lib/libspecimen.so.1" "$b/$role.map"
done
sha256sum --quiet -c "$b/expected-libs.sha256"
test ! -e "$job/runs"; test ! -e "$job/summary.json"
run --build-only --resume "$job" --use unregistered -- good 'two words' '' '*'
expect 0
run --build-only --resume "$job" -- good changed '' '*'
expect 2
run --build-only --out "$tmp/bad" -- fail
expect 23
test "$(cat "$tmp/bad/build/native.exit")" = 23
test ! -e "$tmp/bad/build/bin"; test ! -e "$tmp/bad/runs"
run --build-only --out "$tmp/no-pc" -- no-usage 'two words' '' '*'
if [ "$rc" = 0 ]; then exit 1; fi
grep -Fq 'No native pkg-config usage' "$tmp/run.log"
test ! -e "$tmp/no-pc/build/bin"; test ! -e "$tmp/no-pc/summary.json"
run --build-only --out "$tmp/unresolved" -- missing-lib 'two words' '' '*'
test "$rc" != 0
grep -F 'no private shared library' "$tmp/unresolved/build"/link.*/candidates.tsv |
    grep -Eq '^unresolved[[:space:]]+unresolved[[:space:]]'
test ! -e "$tmp/unresolved/build/bin"

choice=$tmp/choice
run --build-only --out "$choice" -- choice 'two words' '' '*'
test "$rc" != 0; grep -Fq 'Multiple distinct exports' "$tmp/run.log"
test ! -e "$choice/build/bin"; test -f "$choice/build/native.ok"
run --build-only --resume "$choice" --use other -- choice 'two words' '' '*'
expect 0
test "$(cat "$choice/build/module.txt")" = other
for role in client server; do
    grep -Fxq "LOAD $choice/build/prefix/lib/libother.so.1" "$choice/build/$role.map"
done
printf '%s\n' '/* changed after install */' >> "$choice/build/prefix/public/specimen_config.h"
run --build-only --resume "$choice" --use other -- choice 'two words' '' '*'
expect 2
# --as-needed may discard an extra *direct* input from both loader lists.
# The two linker maps still describe different researcher choices.
run --build-only --out "$tmp/extra" -- extra-input 'two words' '' '*'
if [ "$rc" = 0 ]; then echo 'different direct link inputs silently merged' >&2; exit 1; fi
grep -Fq 'Multiple distinct exports' "$tmp/run.log"
test ! -e "$tmp/extra/build/bin"

# A broken export with a definitive missing symbol must not hide a working one.
run --build-only --out "$tmp/missing-symbol" -- missing-symbol 'two words' '' '*'
expect 0
test "$(cat "$tmp/missing-symbol/build/module.txt")" = unregistered
grep -Eq '^missing-symbol[[:space:]]+incompatible[[:space:]]' "$tmp/missing-symbol/build/candidates.tsv"

# Inject an unclassified linker failure after the normal framework is built.
# The other export remains viable; skipping the failing candidate is not safe.
fw=$tmp/direct-framework
scan=$tmp/io-error
mkdir "$fw" "$scan"
cp -P "$TURTLE_BUILD_DIR/submission-client.o" "$TURTLE_BUILD_DIR/submission-server.o" \
   "$TURTLE_BUILD_DIR"/libturtle_observe.so* "$fw/"
TURTLE_FIXTURE_CXX=$(sed -n 's/^CMAKE_CXX_COMPILER:[^=]*=//p' "$TURTLE_BUILD_DIR/CMakeCache.txt")
export TURTLE_FIXTURE_CXX
cat > "$tmp/link-wrapper" <<'SH'
#!/bin/sh
for arg do
    case $arg in
        */io-error/other/*.map)
            printf '%s\n' '/usr/bin/ld: cannot write output: No space left on device' >&2
            exit 73;;
        */mixed-error/other/*.map)
            printf '%s\n' '/usr/bin/ld: implementation.o: undefined reference to specimen' \
                '/usr/bin/ld: cannot write output: No space left on device' >&2
            exit 1;;
    esac
done
exec "$TURTLE_FIXTURE_CXX" "$@"
SH
chmod +x "$tmp/link-wrapper"
printf 'CMAKE_CXX_COMPILER:FILEPATH=%s\n' "$tmp/link-wrapper" > "$fw/CMakeCache.txt"
failed_diagnosis() {
    if cmake "-DROOT=$t" "-DFRAMEWORK=$fw" "-DJOB=$tmp/extra/build" "-DSCAN=$1" \
        -P "$t/tools/submission-link.cmake" > "$1/report.log" 2>&1; then
        echo 'unclassified link failure silently skipped' >&2; exit 1
    fi
    grep -Eq '^other[[:space:]]+unresolved[[:space:]]+' "$1/candidates.tsv"
    grep -Eq '^unregistered[[:space:]]+viable[[:space:]]+' "$1/candidates.tsv" ||
        { cat "$1/candidates.tsv" >&2; exit 1; }
    test "$(cat "$1/other/client.link.log.exit")" = "$2"
    grep -Fq 'No space left on device' "$1/other/client.link.log"
    test ! -e "$tmp/extra/build/bin"
}
failed_diagnosis "$scan" 73
mkdir "$tmp/mixed-error"
failed_diagnosis "$tmp/mixed-error" 1

# Same bridge, but only the server role references a second private DSO.
# The current manifest describes a common set and must not publish a union.
printf '%s\n' 'extern "C" int extra(void); int server_extra() { return extra(); }' > "$tmp/server-extra.cpp"
"$TURTLE_FIXTURE_CXX" -c "$tmp/server-extra.cpp" -o "$tmp/server-extra.o"
"$TURTLE_FIXTURE_CXX" -r -nostdlib "$fw/submission-server.o" "$tmp/server-extra.o" -o "$tmp/combined.o"
mv "$tmp/combined.o" "$fw/submission-server.o"
scan=$tmp/asymmetric
mkdir "$scan"
if TURTLE_USE_MODULE=other cmake "-DROOT=$t" "-DFRAMEWORK=$fw" "-DJOB=$tmp/extra/build" "-DSCAN=$scan" \
    -P "$t/tools/submission-link.cmake" > "$tmp/asymmetric.log" 2>&1; then
    echo 'role-specific private SDK paths silently unioned' >&2; exit 1
fi
grep -Eq '^other[[:space:]]+unresolved[[:space:]]+client and server resolve different private libraries' "$scan/candidates.tsv"
test ! -e "$tmp/extra/build/bin"
printf '%s\n' 'PASS: exact argv, private SDK, both links, equivalent/distinct/unresolved plans, explicit resume, changed inputs/stage rejected'
