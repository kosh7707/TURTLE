#!/bin/sh
# A new source checkout must teach the API, not build or benchmark fake TLS.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
t=$tmp/TURTLE
mkdir -p "$t/implementations" "$t/tools" "$tmp/bin"
cp "$root/bench.sh" "$t/"
cp -R "$root/tools/submission-starter" "$t/tools/"
starter=$t/tools/submission-starter
slot=$t/implementations
cp -p "$starter/build.sh" "$starter/implementation.cpp" "$slot/"
test -x "$slot/build.sh"
printf '%s\n' '#!/bin/sh' 'touch "$GUARD"; exit 99' > "$tmp/bin/cmake"
chmod +x "$tmp/bin/cmake"
export GUARD="$tmp/cmake-called" TURTLE_BUILD_DIR="$tmp/build" TURTLE_OUTPUT_DIR="$tmp/runs"
export PATH="$tmp/bin:$PATH"
reject() {
    rc=0
    (cd / && "$t/bench.sh" "$@") >"$tmp/err" 2>&1 || rc=$?
    test "$rc" = 2 || { cat "$tmp/err" >&2; exit 1; }
    for absent in "$GUARD" "$TURTLE_BUILD_DIR" "$TURTLE_OUTPUT_DIR" "$tmp/explicit"; do test ! -e "$absent"; done
}
reject
grep -Fq 'Starter: implementations/build.sh' "$tmp/err"
grep -Fq 'Starter: implementations/implementation.cpp' "$tmp/err"
grep -Fq 'tools/init-submission-example.sh' "$tmp/err"
reject --build-only --out "$tmp/explicit"
# One edited half does not activate the other one. Use an executable that must not run.
printf '%s\n' '#!/bin/sh' 'touch "$GUARD"; exit 87' > "$slot/build.sh"
reject --build-only
grep -Fq 'Starter: implementations/implementation.cpp' "$tmp/err"
if grep -Fq 'Starter: implementations/build.sh' "$tmp/err"; then exit 1; fi
cp -p "$starter/build.sh" "$slot/build.sh"
printf '%s\n' '// my bridge' > "$slot/implementation.cpp"
reject
grep -Fq 'Starter: implementations/build.sh' "$tmp/err"
if grep -Fq 'Starter: implementations/implementation.cpp' "$tmp/err"; then exit 1; fi
chmod -x "$slot/build.sh"
reject
grep -Fq 'chmod +x implementations/build.sh' "$tmp/err"
rm "$slot/implementation.cpp"
reject
grep -Fq 'Missing submission input: implementations/implementation.cpp' "$tmp/err"

# Even outside bench.sh the starter recipe cannot report success.
mkdir "$tmp/work" "$tmp/prefix"
rc=0; "$starter/build.sh" "$tmp/work" "$tmp/prefix" >"$tmp/recipe.log" 2>&1 || rc=$?
test "$rc" = 2; test -z "$(ls -A "$tmp/work")"; test -z "$(ls -A "$tmp/prefix")"
echo 'PASS: inactive and partial starters fail before writes; the starter recipe cannot produce a staged SDK.'
