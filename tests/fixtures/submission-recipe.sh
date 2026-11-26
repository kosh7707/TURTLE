#!/bin/sh
set -eu
w=$1 p=$2
case $w:$p in /*:/*) ;; *) exit 79;; esac
test "$w" != "$p"
test -d "$w"; test -d "$p"
test -z "$(ls -A "$w")"; test -z "$(ls -A "$p")"
test -f "./not a catalog entry/thing.c"
shift 2
case ${1-} in fail) exit 23;; esac
test "$#" = 4; test "$2" = 'two words'; test "$3" = ''; test "$4" = '*'
mkdir -p "$p/public" "$p/lib" "$p/usage"
printf '%s\n' '#define SPECIMEN_SETTING 5' > "$w/specimen_config.h"
cc -fPIC -shared -Wl,-soname,libspecimen.so.1 "./not a catalog entry/thing.c" -o "$w/libspecimen.so.1"
cp "$w/specimen_config.h" "$p/public/"
cp "$w/libspecimen.so.1" "$p/lib/"; ln -s libspecimen.so.1 "$p/lib/libspecimen.so"
case $1 in no-usage) exit 0;; good|choice|extra-input|missing-lib|missing-symbol) ;; *) exit 2;; esac
printf '%s\n' 'Name: Any submission' 'Description: Build contract test' 'Version: 1' \
    "Cflags: -I$p/public" "Libs: -L$p/lib -lspecimen" > "$p/usage/unregistered.pc"
# Adapted from the study's alpha/alpha-alias/beta consumer plans.
cp "$p/usage/unregistered.pc" "$p/usage/z-alias.pc"
case $1 in
    choice|extra-input)
        other_source="./not a catalog entry/thing.c"
        if [ "$1" = extra-input ]; then
            other_source=$w/extra.c
            printf '%s\n' 'int extra(void) { return 7; }' > "$other_source"
        fi
        cc -fPIC -shared -Wl,-soname,libother.so.1 "$other_source" -o "$p/lib/libother.so.1"
        ln -s libother.so.1 "$p/lib/libother.so"
        flags=-lother
        [ "$1" != extra-input ] || flags='-lspecimen -lother'
        sed "s/-lspecimen\$/$flags/" "$p/usage/unregistered.pc" > "$p/usage/other.pc";;
    missing-lib)
        sed 's/-lspecimen$/-lnot_staged/' "$p/usage/unregistered.pc" > "$p/usage/unresolved.pc";;
    missing-symbol)
        printf '%s\n' 'int extra(void) { return 7; }' > "$w/extra.c"
        cc -fPIC -shared -Wl,-soname,libother.so.1 "$w/extra.c" -o "$p/lib/libother.so.1"
        ln -s libother.so.1 "$p/lib/libother.so"
        sed 's/-lspecimen$/-lother/' "$p/usage/unregistered.pc" > "$p/usage/missing-symbol.pc";;
esac
