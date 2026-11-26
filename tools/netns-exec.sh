#!/bin/sh
# Keep /run/netns mounts inside the private mount namespace.
set -eu
exec unshare --user --map-root-user --net --mount sh -c '
    mount -t tmpfs tmpfs /run
    ip link set lo up
    exec "$@"
' sh "$@"
