#!/bin/sh
# Offline validation from a source-only export on a Linux host with bubblewrap.
set -eu
umask 077
isolation() {
    for hidden do
        if [ -e "$hidden" ] || [ -L "$hidden" ]; then echo "visible: $hidden" >&2; return 1; fi
        printf 'not visible: %s\n' "$hidden"
    done
    printf 'mount=%s pid=%s net=%s\n' "$(readlink /proc/self/ns/mnt)" "$(readlink /proc/self/ns/pid)" "$(readlink /proc/self/ns/net)"
    cat /proc/self/mountinfo
    ip -brief address
    env | sort
}

if [ "${1-}" = --inside-product ]; then
    run=$2; shift 2
    mkdir -p "$HOME"
    cd "$run/source"
    {
        isolation "$@"
        if command -v jq || [ -x /usr/bin/jq ]; then echo 'jq available in product phase' >&2; exit 1; fi
        printf 'jq unavailable on product PATH=%s\n' "$PATH"
        c++ -E -x c++ -o /dev/null - <<'CPP'
#if __has_include(<nlohmann/json.hpp>) || __has_include(<nlohmann/json_fwd.hpp>)
#error External nlohmann JSON header is visible
#endif
CPP
        mkdir "$run/dependency-probe"
        cat > "$run/dependency-probe/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.20)
project(turtle_dependency_probe LANGUAGES CXX)
find_package(nlohmann_json QUIET CONFIG)
if(nlohmann_json_FOUND)
  message(FATAL_ERROR "External nlohmann JSON CMake package is visible")
endif()
CMAKE
        cmake -S "$run/dependency-probe" -B "$run/dependency-probe/build"
        printf '%s\n' 'No nlohmann JSON default compiler include or CMake config was found'
        cat /etc/os-release
        cmake --version; c++ --version; make --version; openssl version
        pkg-config --modversion nettle hogweed gmp libtasn1 libidn2 p11-kit-1
    } > "$run/isolation.log" 2>&1
    tools/validation/build-matrix.sh run "$PWD" "$run/inputs" "$run/matrix"
    v="$run/matrix/openssl"
    rc=0
    (
        cd "$v/tree" &&
        TURTLE_BUILD_DIR="$v/framework" ./bench.sh --resume "$v/job" \
            --scenario all --role both --auth both --warmups 1 --repetitions 2 &&
        head -n 1 "$v/job/cases.csv" "$v/job/results.csv" &&
        grep -m 1 '^server,S0,client,passed,' "$v/job/cases.csv" &&
        grep -m 1 '^server,S0,client,sample,' "$v/job/results.csv"
    ) > "$run/scenarios.log" 2>&1 || rc=$?
    printf '%s\n' "$rc" > "$run/scenarios.exit"
    exit "$rc"
fi

if [ "${1-}" = --inside-audit ]; then
    run=$2; shift 2
    mkdir -p "$HOME"
    cd "$run/source"
    {
        isolation "$@"
        jq --version || printf '%s\n' 'jq unavailable for the research audit'
    } > "$run/audit-isolation.log" 2>&1
    v="$run/matrix/openssl"
    rc=$(cat "$run/scenarios.exit")
    # Research-only tools may use jq. Retain both outcomes even after a scenario failure.
    audit=0; tools/validation/index-matrix.sh "$v/job" "$run/index" > "$run/index.log" 2>&1 || audit=$?
    control=0; tools/validation/runtime-controls.sh "$v" "$run/controls" > "$run/controls.log" 2>&1 || control=$?
    printf 'scenario=%s index=%s controls=%s\n' "$rc" "$audit" "$control" > "$run/verification.txt"
    [ "$rc" = 0 ] && [ "$audit" = 0 ] && [ "$control" = 0 ]
    exit "$?"
fi

[ "$#" -ge 2 ] || { echo 'Usage: clean-room.sh PINNED_INPUTS NEW_RUN_DIR [ADDITIONAL_PATHS_TO_HIDE...]' >&2; exit 2; }
src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
inputs=$(realpath -e -- "$1")
run=$(realpath -m -- "$2")
shift 2
# Do not create output in the source checkout, input bundle, or a protected tree.
for hidden in "$src" "$inputs" "$@"; do
    case "$run/" in "$(realpath -m -- "$hidden")/"*) echo "output is inside hidden input: $hidden" >&2; exit 2;; esac
done
mkdir -- "$run"
mkdir "$run/source" "$run/source/implementations" "$run/inputs" "$run/source/docs"
cp -p -- "$src/bench.sh" "$src/CMakeLists.txt" "$src/.gitignore" "$run/source/"
for dir in src tools tests; do cp -a -- "$src/$dir" "$run/source/"; done
cp -a -- "$src/docs/examples" "$run/source/docs/"
# Seed only the distributable pair. Never export the active recipe, bridge or native checkout.
starter=$run/source/tools/submission-starter
cp -p -- "$starter/build.sh" "$starter/implementation.cpp" "$src/implementations/README.md" "$run/source/implementations/"
# Only archive inputs, not any previous prefix, compiled library or build directory.
for file in openssl-2d1c10a592677ff34cdf60bd59c431d835a1fc26.tar.gz wolfssl-5.9.4.tar.gz \
            gnutls-3.8.14.tar.xz; do
    cp -- "$inputs/$file" "$run/inputs/$file"
done
(cd "$run/source"; find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$run/source.sha256"
{
    printf 'mount=%s pid=%s net=%s\n' "$(readlink /proc/self/ns/mnt)" "$(readlink /proc/self/ns/pid)" "$(readlink /proc/self/ns/net)"
    uname -a
} > "$run/host.log"
# Only base OS tools/configuration are inherited. /home, /tmp, /proc (new PID
# namespace), environment, and loopback network are private. Keep the absolute
# run path stable inside/outside so maps, profiles and checksums remain usable.
isolate() {
    env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/tmp/turtle-home JOBS="${JOBS:-4}" \
        CMAKE_BUILD_PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-3}" \
        bwrap --unshare-all --die-with-parent --ro-bind /usr /usr --ro-bind /etc /etc \
          --symlink usr/bin /bin --symlink usr/sbin /sbin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
          --tmpfs /usr/local --proc /proc --dev /dev --tmpfs /tmp --bind "$run" "$run" \
          --ro-bind "$run/source" "$run/source" --ro-bind "$run/inputs" "$run/inputs" \
          --chdir "$run/source" "$@"
}
self="$run/source/tools/validation/clean-room.sh"
product_phase() {
    if [ -e /usr/bin/jq ] || [ -L /usr/bin/jq ]; then
        isolate --ro-bind /dev/null /usr/bin/jq -- "$self" --inside-product "$run" "$@"
    else
        isolate -- "$self" --inside-product "$run" "$@"
    fi
}
rc=0
product_phase "$src" "$inputs" "$@" || rc=$?
if [ ! -f "$run/scenarios.exit" ]; then
    printf 'Product phase stopped before scenarios (exit %s); see %s and build matrix logs.\n' "$rc" "$run/isolation.log" >&2
    [ "$rc" -ne 0 ] || exit 1
    exit "$rc"
fi
# The independent readers may emit new audit/control data, but cannot edit
# the original binaries or connection evidence they are asked to judge.
isolate --ro-bind "$run/matrix" "$run/matrix" -- "$self" --inside-audit "$run" "$src" "$inputs" "$@"
