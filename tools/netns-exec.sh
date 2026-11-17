#!/bin/sh
# /run/netns 마운트도 별도 마운트 네임스페이스 안에서 소유한다.
set -eu
exec unshare --user --map-root-user --net --mount sh -c '
    mount -t tmpfs tmpfs /run
    ip link set lo up
    exec "$@"
' sh "$@"
