#!/bin/sh
set -eu
export LC_ALL=C
fail() { printf '%s\n' "$2" >&2; exit "$1"; }
[ "$#" -ge 3 ] || fail 2 'usage: submission-build.sh ROOT FRAMEWORK_BUILD JOB_DIR [native build arguments...]'
root=$(realpath -e -- "$1")
framework=$(realpath -e -- "$2")
job=$(realpath -m -- "$3")
shift 3
submission=$root/implementations
[ -f "$submission/build.sh" ] && [ -x "$submission/build.sh" ] &&
    [ -f "$submission/implementation.cpp" ] ||
    fail 2 'Missing executable implementations/build.sh or implementations/implementation.cpp'
for input in submission-client.o submission-server.o libturtle_measure.a \
             turtle-submission-job turtle-issue-test-leaves.sh; do
    [ -f "$framework/$input" ] || fail 2 "Missing framework build input: $framework/$input"
done
actual_submission=$(realpath -e -- "$submission")
case "$job/" in "$actual_submission/"*) fail 2 'The build output cannot be inside implementations/';; esac
mkdir -p -- "$job"
exec 9>>"$job/lock"
flock -n 9 || fail 2 "Submission build is already running: $job"
fingerprint() {
    cmake "-DTREE=$1" "-DRECORD=$2" -P "$root/tools/submission-fingerprint.cmake"
}
work=$job/work
prefix=$job/prefix
fingerprint "$submission" "$job/submission.current.sha256"
printf '%s\0' "$actual_submission" "$@" > "$job/native-arguments.current"
printf '%s\0' "${CC-}" "${CXX-}" "${CFLAGS-}" "${CXXFLAGS-}" "${CPPFLAGS-}" "${LDFLAGS-}" "${PATH-}" \
    "${CMAKE_PREFIX_PATH-}" "${CMAKE_TOOLCHAIN_FILE-}" "${CONFIG_SITE-}" "${PKG_CONFIG_PATH-}" "${PKG_CONFIG_LIBDIR-}" \
    | sha256sum > "$job/native-environment.current.sha256"
if [ -f "$job/native.ok" ]; then
    if ! cmp -s "$job/submission.current.sha256" "$job/submission.sha256" ||
       ! cmp -s "$job/native-arguments.current" "$job/native-arguments" ||
       ! cmp -s "$job/native-environment.current.sha256" "$job/native-environment.sha256"; then
        fail 2 "Submission, native arguments, or recorded build environment changed; use a fresh job directory: $job"
    fi
    fingerprint "$prefix" "$job/prefix.current.sha256"
    cmp -s "$job/prefix.current.sha256" "$job/prefix.sha256" ||
        fail 2 "The staged TLS install changed; use a fresh job directory: $job"
else
    [ ! -e "$work" ] && [ ! -e "$prefix" ] ||
        fail 2 "Previous native build incomplete; use a fresh job directory: $job"
    mkdir -- "$work" "$prefix"
    cp -- "$job/submission.current.sha256" "$job/submission.sha256"
    cp -- "$job/native-arguments.current" "$job/native-arguments"
    cp -- "$job/native-environment.current.sha256" "$job/native-environment.sha256"
    printf '%s\n' "Building submitted TLS source (log: $job/native.log)"
    rc=0
    ( cd -- "$submission" && ./build.sh "$work" "$prefix" "$@" ) > "$job/native.log" 2>&1 || rc=$?
    printf '%s\n' "$rc" > "$job/native.exit"
    if [ "$rc" -ne 0 ]; then
        tail -n 12 -- "$job/native.log" >&2
        fail "$rc" "implementations/build.sh failed ($rc): $job/native.log"
    fi
    fingerprint "$submission" "$job/submission.after.sha256"
    cmp -s "$job/submission.after.sha256" "$job/submission.sha256" ||
        fail 2 'implementations/build.sh changed the submission; put all native build changes in the provided work directory'
    fingerprint "$prefix" "$job/prefix.sha256"
    touch -- "$job/native.ok"
fi
if [ -e "$job/reuse.sha256" ] || [ -L "$job/reuse.sha256" ]; then
    [ -z "${TURTLE_USE_MODULE-}" ] || [ "$TURTLE_USE_MODULE" = "$(cat "$job/module.txt")" ] ||
        fail 2 "The build is already linked for a different module; select with --use in a fresh build job"
    sh "$root/tools/submission-receipt.sh" verify "$job"
    exit
fi
scan=$(mktemp -d -- "$job/link.XXXXXXXX")
mkdir -- "$scan/runtime"
for input in turtle-submission-job turtle-issue-test-leaves.sh; do
    cp -pL -- "$framework/$input" "$scan/runtime/"
done
# Unsealed previous selection attempts can safely receive a fresh snapshot.
if [ -e "$job/runtime" ] || [ -L "$job/runtime" ]; then
    mv -T -- "$job/runtime" "$scan/previous-runtime"
fi
mv -T -- "$scan/runtime" "$job/runtime"
unset CPATH CPLUS_INCLUDE_PATH C_INCLUDE_PATH LIBRARY_PATH LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT LD_DEBUG LD_DEBUG_OUTPUT
cmake "-DROOT=$root" "-DFRAMEWORK=$framework" "-DJOB=$job" "-DSCAN=$scan" -P "$root/tools/submission-link.cmake"
sh "$root/tools/submission-receipt.sh" seal "$job"
