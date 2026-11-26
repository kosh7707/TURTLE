#!/bin/sh
set -eu
umask 077
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
xdg_base() {
    case $1 in /*) printf '%s\n' "$1"; return;; esac
    case ${HOME-} in
        /*) printf '%s/%s\n' "$HOME" "$2";;
        *) echo 'Set an absolute HOME or XDG directory, or select explicit build/output paths.' >&2; return 2;;
    esac
}
external_path() {
    path=$(realpath -m -- "$1") || return
    case "$path/" in
        "$root/"*) echo "Default storage must be outside the checkout: $path" >&2; return 2;;
    esac
    printf '%s\n' "$path"
}
default_build_dir() {
    cache=$(xdg_base "${XDG_CACHE_HOME-}" .cache) || return
    # Physical paths distinguish checkouts with the same name and let a
    # symlink to a checkout reuse its cache. SDK and submission modes differ.
    key=$(printf '%s' "$root" | sha256sum) || return
    external_path "$cache/turtle/${key%% *}/$1"
}
default_output_dir() {
    data=$(xdg_base "${XDG_DATA_HOME-}" .local/share) || return
    external_path "$data/turtle/runs"
}
usage() {
    printf '%s\n' "Usage: $0 [--scenario S0|S1|S2|S3|S4|all] [--role client|server|both] [--auth server|mtls|both]" \
        '       [--warmups N] [--repetitions N] [--tcp-nodelay on|off] [--out NEW_DIRECTORY] [--credentials DIR] [--use MODULE] [-- NATIVE_ARGS...]' \
        '       TCP_NODELAY defaults to on for both submission sockets; set off to measure with Nagle enabled.' \
        "       $0 --build-only [--out NEW_DIRECTORY | --resume PREVIOUS_OUTPUT] [--use MODULE] [-- NATIVE_ARGS...]" \
        '       --build-only links both role binaries and stops before doctor. No TLS connections or performance results.' \
        '       Resume a staged build without existing runs: --resume PREVIOUS_OUTPUT [--use MODULE] [-- same native args...]' \
        '       Run a linked build without rebuilding: --run-from BUILD_JOB [--out NEW_RUN] [run options]' \
        '       First run: edit implementations/build.sh and implementation.cpp; the shipped starters do not run TLS.' \
        '       Optional: tools/init-submission-example.sh NAME (e.g. openssl); never chooses or downloads a library.' \
        '       Uses implementations/build.sh and implementation.cpp. Defaults: S3, client, server authentication, 1 warmup, 2 samples.' \
        "       Existing SDK profile: $0 PROFILE.json [NEW_OUTPUT] | --client APP [ARGS...] | --server APP [ARGS...] | --pair" \
        '       Defaults: build cache under XDG_CACHE_HOME/turtle; runs under XDG_DATA_HOME/turtle/runs.' \
        '       Override with TURTLE_BUILD_DIR or TURTLE_OUTPUT_DIR; otherwise fall back to ~/.cache and ~/.local/share.'
}
legacy() {
    role=
    case $1 in
        --client|--server) role=${1#--}; shift; [ "$#" -ge 1 ] || { usage >&2; exit 2; };;
        --pair) shift; [ "$#" = 0 ] || { usage >&2; exit 2; };;
        *) [ "$#" -le 2 ] || { usage >&2; exit 2; };;
    esac
    fw=${TURTLE_BUILD_DIR:-$(default_build_dir legacy)}
    base=
    if [ -z "$role" ] && [ "$#" = 2 ]; then out=$2; else
        base=${TURTLE_OUTPUT_DIR:-$(default_output_dir)}
    fi
    cmake -S "$root" -B "$fw" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DTURTLE_BUILD_REFERENCE=ON
    cmake --build "$fw" --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
    if [ -n "$base" ]; then
        mkdir -p -- "$base"
        parent=$(mktemp -d -- "$base/run-XXXXXXXX"); out=$parent/results
    fi
    printf 'Outputs: %s\n' "$out"
    if [ -n "$role" ]; then exec "$fw/turtle" target "$role" "$out" "$@"; fi
    if [ "$#" = 0 ]; then exec "$fw/turtle-pair" "$out"; fi
    exec "$fw/turtle" run "$1" "$out"
}
case ${1-} in
    -h|--help) usage; exit 0;;
    --client|--server|--pair) legacy "$@";;
    -*) ;;
    '') ;;
    *) legacy "$@";;
esac
role=client scenario=S3 auth=server warmups=1 repetitions=2 out= credentials= resume= build_only= run_options= nodelay=on
run_from= use_option=
while [ "$#" != 0 ]; do
    case $1 in
      --) shift; break;;
      --build-only) build_only=yes; shift; continue;;
      --role|--scenario|--auth|--warmups|--repetitions|--credentials|--tcp-nodelay) run_options=yes;;
    esac
    [ "$#" -ge 2 ] || { usage >&2; exit 2; }
    case $1 in
      --role) role=$2;; --scenario) scenario=$2;; --auth) auth=$2;;
      --warmups) warmups=$2;; --repetitions) repetitions=$2;; --out) out=$2;;
      --tcp-nodelay) nodelay=$2;;
      --resume) resume=$2;;
      --run-from) [ -n "$2" ] || { usage >&2; exit 2; }; run_from=$2;;
      --use) use_option=yes; TURTLE_USE_MODULE=$2; export TURTLE_USE_MODULE;;
      --credentials) [ -n "$2" ] || { usage >&2; exit 2; }; credentials=$2;;
      *) usage >&2; exit 2;;
    esac
    shift 2
done
[ -z "$build_only" ] || [ -z "$run_options" ] || { echo '--build-only does not accept run options' >&2; exit 2; }
if [ -n "$credentials" ]; then credentials=$(realpath -e -- "$credentials"); fi
case $role in client|server|both) ;; *) usage >&2; exit 2;; esac
case $scenario in S[0-4]|all) ;; *) usage >&2; exit 2;; esac
case $auth in server|mtls|both) ;; *) usage >&2; exit 2;; esac
case $nodelay in on|off) ;; *) usage >&2; exit 2;; esac
for count in "$warmups" "$repetitions"; do
    case $count in ''|*[!0-9]*) usage >&2; exit 2;; esac
    [ "$count" -le 100000 ] || { usage >&2; exit 2; }
done
[ "$repetitions" -ge 1 ] || { usage >&2; exit 2; }

run_locked() {
    build=$1
    area=$2
    destination=$3
    unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH LD_DEBUG LD_DEBUG_OUTPUT TURTLE_PMU
    export TURTLE_TCP_NODELAY=$nodelay
    # Verify with trusted checkout code before handing this PID (and lock)
    # to a sealed binary. The checker owns hashing until it can exec.
    exec env --default-signal=INT,TERM sh "$root/tools/submission-receipt.sh" \
        run "$build" "$area" "$destination" \
        "$role" "$scenario" "$auth" "$warmups" "$repetitions" "$credentials"
}
lock_build() {
    [ -d "$1" ] && [ ! -L "$1" ] && [ -f "$1/lock" ] && [ ! -L "$1/lock" ] &&
        [ -f "$1/reuse.sha256" ] && [ ! -L "$1/reuse.sha256" ] || {
        echo "Not a reusable linked submission: $1 (run --build-only in a fresh job)" >&2
        exit 2
    }
    exec 9<"$1/lock"
    flock -sn 9 || { echo "Submission build is being updated: $1" >&2; exit 2; }
}
if [ -n "$run_from" ]; then
    [ -z "$resume$build_only$use_option${TURTLE_USE_MODULE-}" ] && [ "$#" = 0 ] ||
        { echo '--run-from does not accept --build-only, --resume, --use or native build arguments' >&2; exit 2; }
    old=$(realpath -e -- "$run_from") ||
        { echo "Build job does not exist: $run_from" >&2; exit 2; }
    # Runtime scratch and local retry receipts must not mutate a prior run.
    for external in "${TMPDIR:-/tmp}" "${XDG_STATE_HOME:-${HOME:+$HOME/.local/state}}"; do
        [ -n "$external" ] || continue
        case "$(realpath -m -- "$external")/" in
            "$old/"*) echo 'Runtime scratch/state must be outside the original build job' >&2; exit 2;;
        esac
    done
    lock_build "$old/build"
    slot=$(realpath -m -- "$root/implementations")
    if [ -n "$out" ]; then
        new=$(realpath -m -- "$out")
    else
        new=$(realpath -m -- "${TURTLE_OUTPUT_DIR:-$(default_output_dir)}")
    fi
    case "$new/" in
        "$old/"*|"$slot/"*) echo 'New run must be outside the original build job and implementations/' >&2; exit 2;;
    esac
    if [ -n "$out" ]; then
        [ ! -e "$out" ] && [ ! -L "$out" ] && [ ! -e "$new" ] ||
            { echo "Run output already exists: $out" >&2; exit 2; }
        area=new
    else
        area=default
    fi
    run_locked "$old/build" "$area" "$new"
fi
# A distribution has editable starters, not a benchmarkable TLS submission.
# Check each file before creating a job, even when the other half is ready.
ready=yes
for name in build.sh implementation.cpp; do
    input=$root/implementations/$name
    if [ ! -f "$input" ]; then
        echo "Missing submission input: implementations/$name" >&2
    elif [ "$name" = build.sh ] && [ ! -x "$input" ]; then
        echo 'Recipe is not executable: chmod +x implementations/build.sh' >&2
    elif cmp -s -- "$root/tools/submission-starter/$name" "$input"; then
        echo "Starter: implementations/$name still contains the shipped template." >&2
    else
        case $? in
            1) continue;;  # Different content: let the real build check it.
            *) echo "Cannot compare implementations/$name with its starter in tools/submission-starter/." >&2;;
        esac
    fi
    ready=no
done
if [ "$ready" = no ]; then
    printf '%s\n' 'Edit the indicated files for your TLS library, then run ./bench.sh --build-only.' \
        'Or select an example: tools/init-submission-example.sh openssl (native source must be supplied separately).' \
        'See implementations/README.md. No build or benchmark was started.' >&2
    exit 2
fi
slot=$(realpath -e -- "$root/implementations")
fw=${TURTLE_BUILD_DIR:-$(default_build_dir submission)}
fw=$(realpath -m -- "$fw")
base=
if [ -z "$resume" ] && [ -z "$out" ]; then
    base=${TURTLE_OUTPUT_DIR:-$(default_output_dir)}
fi
for writable in "$fw" "${resume:-${out:-$base}}"; do
    case "$(realpath -m -- "$writable")/" in "$slot/"*) echo 'Build and output directories must be outside implementations/' >&2; exit 2;; esac
done
if [ -n "$resume" ]; then
    [ -z "$out" ] && [ -f "$resume/build/native.ok" ] && [ ! -e "$resume/runs" ] || { echo 'Resume is for a pending native build without benchmark cases' >&2; exit 2; }
    out=$(realpath -e -- "$resume")
elif [ -n "$out" ]; then
    mkdir -p -- "$(dirname -- "$out")"; mkdir -- "$out"; out=$(realpath -e -- "$out")
else
    mkdir -p -- "$base"
    out=$(realpath -e -- "$(mktemp -d -- "$base/submission-XXXXXXXX")")
fi
printf 'Submission: %s/implementations\nResults: %s\n' "$root" "$out"
cmake -S "$root" -B "$fw" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DTURTLE_BUILD_REFERENCE=OFF
cmake --build "$fw" --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-2}" --target turtle turtle_observe turtle-submission-roles turtle-submission-job
"$root/tools/submission-build.sh" "$root" "$fw" "$out/build" "$@"
if [ -n "$build_only" ]; then
    printf 'Build only: %s/build/bin/{client,server}; no connections were started.\n' "$out"
    exit 0
fi
lock_build "$out/build"
run_locked "$out/build" existing "$out"
