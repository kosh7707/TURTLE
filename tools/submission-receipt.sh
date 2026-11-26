#!/bin/sh
# Seal exactly the files needed to run one selected build. No CMake cache
# or source checkout is needed to check it. The snapshot is not relocatable.
set -eu
export LC_ALL=C
umask 077
[ "$#" -ge 2 ] || exit 2
mode=$1
build=$(realpath -e -- "$2") || exit 2
shift 2
case $mode in
    seal|verify) [ "$#" = 0 ] || exit 2;;
    run) [ "$#" = 10 ] || exit 2;;
    *) exit 2;;
esac
bad() { echo "Incomplete, changed, or relocated submission build: $build (use a freshly linked build job)" >&2; exit 2; }
case "$build" in *'
'*) bad;; esac
for dir in runtime bin prefix; do
    [ -d "$build/$dir" ] && [ ! -L "$build/$dir" ] || bad
done
state= writer= reader= pending= stopped=0 waiting=no
owned_child() {
    while read -r field value rest; do
        if [ "$field" = PPid: ]; then
            [ "$value" = "$$" ]; return
        fi
    done < "/proc/$1/status" 2>/dev/null
    return 1
}
cleanup() {
    trap '' INT TERM
    for pid in "$writer" "$reader"; do
        [ -n "$pid" ] || continue
        if owned_child "$pid"; then
            # The workers start their own sessions. The direct-PID fallback
            # covers cancellation before setsid(2) has run in a worker.
            kill -KILL "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || :
        fi
    done
    for pid in "$writer" "$reader"; do
        [ -z "$pid" ] || { wait "$pid" 2>/dev/null || :; }
    done
    [ -z "$pending" ] || rm -f -- "$pending"
    [ -z "$state" ] || rm -rf -- "$state"
}
on_stop() {
    stopped=$1
    # Outside wait, defer exit until an asynchronous worker's $! has been
    # recorded. A signal received before wait cannot be lost.
    if [ "$waiting" = yes ]; then exit "$stopped"; fi
}
check_stop() { [ "$stopped" = 0 ] || exit "$stopped"; }
wait_worker() {
    waiting=yes
    check_stop
    code=0
    wait "$1" || code=$?
    waiting=no
    if [ "$1" = "$writer" ]; then writer=; else reader=; fi
    check_stop
    return "$code"
}
trap cleanup EXIT
trap 'on_stop 130' INT
trap 'on_stop 143' TERM
state=$(mktemp -d -- /tmp/turtle-submission-receipt.XXXXXXXX)
check_stop
mkfifo -- "$state/prefix"
setsid sh -c 'exec tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --exclude-vcs -cf - -C "$1" . > "$2"' tar "$build/prefix" "$state/prefix" &
writer=$!
check_stop
setsid sh -c 'exec sha256sum < "$1" > "$2"' sha256sum \
    "$state/prefix" "$state/prefix.sha256" &
reader=$!
result=0
# A stopped hash reader can leave tar waiting to open the FIFO. On reader
# error the EXIT cleanup stops the writer rather than waiting on that open.
wait_worker "$reader" || bad
wait_worker "$writer" || result=$?
[ "$result" = 0 ] || bad

bins='bin/client bin/server runtime/turtle-submission-job runtime/turtle-issue-test-leaves.sh'
files='module.txt client.map server.map implementation.d link-evidence.txt
       native.log native.exit native.ok native-arguments native-environment.sha256
       submission.sha256 prefix.sha256 expected-libs.txt expected-libs.sha256'
for required in $bins; do [ -x "$build/$required" ] || bad; done
for required in $bins $files; do
    [ -f "$build/$required" ] && [ ! -L "$build/$required" ] || bad
done
[ "$(cat "$build/native.exit")" = 0 ] || bad
setsid sh -c 'cd -- "$1"; shift; exec sha256sum -- "$@"' sha256sum \
    "$build" $bins $files > "$state/files.sha256" &
reader=$!
wait_worker "$reader" || bad
{
    printf '%s\n' 'turtle-submission-reuse-v2' "$build"
    cat -- "$state/prefix.sha256" "$state/files.sha256"
} > "$state/computed"
check_stop
case $mode in
    seal)
        # Trusted caller holds the producer lock. Publish only a complete seal.
        [ ! -e "$build/reuse.sha256" ] && [ ! -L "$build/reuse.sha256" ] || bad
        [ ! -e "$build/reuse.sha256.pending" ] && [ ! -L "$build/reuse.sha256.pending" ] || bad
        pending=$build/reuse.sha256.pending
        cp -- "$state/computed" "$pending"
        check_stop
        mv -T -- "$pending" "$build/reuse.sha256"
        pending=
        ;;
    verify|run)
        [ -f "$build/reuse.sha256" ] && [ ! -L "$build/reuse.sha256" ] &&
            cmp -s -- "$state/computed" "$build/reuse.sha256" || bad
        ;;
esac
check_stop
if [ "$mode" = run ]; then
    tool_path=/usr/sbin:/usr/bin:/sbin:/bin
    for utility in unshare ip tc ping; do
        PATH=$tool_path command -v "$utility" >/dev/null 2>&1 ||
            { printf 'Benchmark requires %s to configure and check the veth link.\n' "$utility" >&2; exit 2; }
    done
    unshare=$(PATH=$tool_path command -v unshare)
    # Exec the selected runtime only after the receipt has been checked;
    # this is also the first operation allowed to allocate a reused run.
    area=$1; destination=$2; shift 2
    case $area in
        existing) ;;
        new)
            mkdir -p -- "$(dirname -- "$destination")"
            mkdir -- "$destination";;
        default)
            mkdir -p -- "$destination"
            destination=$(mktemp -d -- "$destination/submission-XXXXXXXX");;
        *) exit 2;;
    esac
    rm -rf -- "$state"
    state=
    # No worker or scratch remains; from here a stop must exit immediately
    # rather than setting a flag that exec could otherwise forget.
    waiting=yes
    check_stop
    if [ "$area" != existing ]; then
        printf 'Build: %s\nResults: %s\n' "$(dirname -- "$build")" "$destination"
    fi
    digest=$(sha256sum < "$build/reuse.sha256")
    TURTLE_BUILD_ID=${digest%% *}
    export TURTLE_BUILD_ID
    set -- "$build/runtime/turtle-submission-job" "$build" "$destination" "$@"
    if [ "$(id -u)" != 0 ]; then
        set -- --user --map-root-user --net -- "$@"
    else
        set -- --net -- "$@"
    fi
    exec env --default-signal=INT,TERM "$unshare" "$@"
fi
