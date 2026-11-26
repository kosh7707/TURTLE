#!/bin/sh
# Run controls independently and preserve both outcomes, even if one fails.
set -eu
umask 077
if [ "$#" -ne 2 ]; then
    printf 'usage: %s OPENSSL_VENDOR_RUN_DIR NEW_OUTPUT\n' "$0" >&2
    exit 2
fi
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
vendor=$(realpath -e "$1")
mkdir -- "$2"
out=$(realpath -e "$2")
ok=true
for control in handshake-failure openssl-greeting-control; do
    rc=0
    "$here/$control.sh" "$vendor/framework" "$vendor/job" "$out/$control" \
        >"$out/$control.command.log" 2>&1 || rc=$?
    printf '%s\n' "$rc" >"$out/$control.exit"
    [ "$rc" -eq 0 ] || ok=false
done
"$ok"
