#!/bin/sh
# Explicitly select a complete recipe and bridge without changing native sources.
set -eu
umask 077
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
starter=$root/tools/submission-starter
slot=$root/implementations
reject() { printf '%s\n' "$*" >&2; exit 2; }
[ "$#" = 1 ] || reject 'Usage: tools/init-submission-example.sh NAME (see docs/examples/submissions/README.md)'
case $1 in
    ''|-*|*[!a-zA-Z0-9_-]*) reject 'Invalid example name. See docs/examples/submissions/README.md.';;
esac
name=$1
example=$root/docs/examples/submissions/$name
[ -d "$example" ] && [ ! -L "$example" ] ||
    reject "Unknown example '$name'. See docs/examples/submissions/README.md."
for file in build.sh implementation.cpp; do
    [ -f "$example/$file" ] && [ ! -L "$example/$file" ] ||
        reject "'$name' does not include $file. See docs/examples/submissions/README.md or write your own bridge."
    [ -f "$starter/$file" ] && [ ! -L "$starter/$file" ] ||
        reject "Shipped starter missing: tools/submission-starter/$file. Restore it before selecting an example."
done
[ -d "$slot" ] && [ ! -L "$slot" ] ||
    reject 'implementations/ must be a real directory, not a symlink.'
cd -- "$slot"
# Serialize invocations of this helper without writing a lockfile into the slot.
exec 9< .
flock -n 9 || reject 'Another example selection is in progress.'
[ ! -L "$slot" ] && [ . -ef "$slot" ] ||
    reject 'implementations/ changed during selection; no files installed.'

occupied() { [ -e "$1" ] || [ -L "$1" ]; }
check_slot() {
    for file in build.sh implementation.cpp; do
        if [ -L "$file" ] || { [ -e "$file" ] &&
            { [ ! -f "$file" ] || ! cmp -s -- "$starter/$file" "$file"; }; }; then
            reject "Keeping implementations/$file: it is not the untouched starter. Save your work elsewhere before selecting an example."
        fi
    done
}
check_slot

stage=$(mktemp -d -- "$root/.submission-example.XXXXXXXX")
finish() {
    rc=$?
    trap - EXIT HUP INT TERM
    recovery=no
    if [ "$rc" != 0 ] && [ -d "$stage/published" ]; then
        for file in build.sh implementation.cpp; do
            # Never remove a file placed or edited by someone else after our rename.
            if [ ! -e "$stage/new/$file" ] && [ -f "$stage/published/$file" ] &&
                [ ! -L "$file" ] && [ "$file" -ef "$stage/published/$file" ] &&
                cmp -s -- "$example/$file" "$file"; then
                rm -- "$file" || recovery=yes
            fi
            if occupied "$stage/old/$file"; then
                if ! mv -nT -- "$stage/old/$file" "$file" ||
                    occupied "$stage/old/$file"; then
                    recovery=yes
                fi
            fi
        done
    fi
    if [ "$recovery" = yes ]; then
        printf 'Could not complete rollback. Preserved staging and any originals at %s.\n' "$stage" >&2
        exit "$rc"
    fi
    rm -rf -- "$stage"
    exit "$rc"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
[ "$(stat -c %d -- .)" = "$(stat -c %d -- "$stage")" ] ||
    reject 'implementations/ and its checkout must be on the same filesystem.'
mkdir -- "$stage/new" "$stage/old" "$stage/published"
install -m755 -- "$example/build.sh" "$stage/new/build.sh"
install -m644 -- "$example/implementation.cpp" "$stage/new/implementation.cpp"
check_slot
for file in build.sh implementation.cpp; do
    ln -- "$stage/new/$file" "$stage/published/$file"
done
for file in build.sh implementation.cpp; do
    # Move before checking again, so a concurrent replacement is preserved
    # in the original backup, never overwritten by the new file.
    if occupied "$file"; then
        mv -nT -- "$file" "$stage/old/$file"
        old=$stage/old/$file
        [ ! -L "$old" ] && [ -f "$old" ] &&
            cmp -s -- "$starter/$file" "$old" ||
            reject "implementations/$file changed during selection; not replacing it."
    fi
    mv -nT -- "$stage/new/$file" "$file"
    [ ! -e "$stage/new/$file" ] ||
        reject "implementations/$file appeared during selection; not replacing it."
done
printf 'Selected %s: installed build.sh and implementation.cpp. Native sources are unchanged.\n' "$name"
printf '%s\n' 'Prepare the native sources as documented, then run ./bench.sh --build-only from the checkout root.'
