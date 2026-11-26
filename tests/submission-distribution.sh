#!/bin/sh
# Release-only gate: inspect a real extracted archive, not a customized slot.
set -eu
[ "$#" = 1 ] || { echo 'Usage: sh tests/submission-distribution.sh EXTRACTED_RELEASE' >&2; exit 2; }
root=$(CDPATH='' cd -- "$1" && pwd -P)
slot=$root/implementations
factory=$root/tools/submission-starter
fail() { printf 'Invalid distribution: %s\n' "$*" >&2; exit 1; }
for d in "$slot" "$factory"; do
    [ -d "$d" ] && [ ! -L "$d" ] || fail "expected a real directory: $d"
done
[ -f "$slot/README.md" ] && [ ! -L "$slot/README.md" ] || fail 'missing regular implementations/README.md'
for name in build.sh implementation.cpp; do
    for dir in "$slot" "$factory"; do
        [ -f "$dir/$name" ] && [ ! -L "$dir/$name" ] || fail "missing regular file: $dir/$name"
    done
    cmp -s -- "$slot/$name" "$factory/$name" || fail "active $name is not the shipped template"
done
[ -x "$slot/build.sh" ] && [ -x "$factory/build.sh" ] || fail 'starter recipe is not executable'
extra=$(find "$slot" -mindepth 1 -maxdepth 1 ! -name README.md ! -name build.sh ! -name implementation.cpp -print -quit)
[ -z "$extra" ] || fail "unexpected submission payload: $extra"
echo 'PASS: extracted release ships both exact starters, an executable recipe and no private submission inputs.'
