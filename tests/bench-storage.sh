#!/bin/sh
# Check the entry point's path and dispatch contract without building TLS.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
tmp=$(mktemp -d)
trap 'rc=$?; if [ "$rc" != 0 ] && [ -f "$tmp/run.log" ]; then cat "$tmp/run.log" >&2; fi; rm -rf -- "$tmp"' EXIT
tmp=$(realpath -e -- "$tmp")
mkdir -p "$tmp/bin" "$tmp/caller"
cat > "$tmp/bin/cmake" <<'SH'
#!/bin/sh
set -eu
case $1 in
    -S)
        [ "$3" = -B ]
        mkdir -p -- "$4"
        printf '%s\n' "$2" > "$4/source.txt"
        ;;
    --build)
        [ -f "$2/source.txt" ]
        for executable in turtle turtle-pair; do
            cp -- "$TEST_RUNTIME" "$2/$executable"
        done
        ;;
    *) exit 70;;
esac
SH
cat > "$tmp/runtime" <<'SH'
#!/bin/sh
set -eu
case ${0##*/}:$1 in
    turtle-pair:*) out=$1;;
    turtle:run|turtle:target) out=$3;;
    *) exit 70;;
esac
mkdir -- "$out"
printf '%s\n' "$@" > "$out/argv"
exit "${TEST_RUNTIME_RC:-0}"
SH
cat > "$tmp/submission" <<'SH'
#!/bin/sh
set -eu
[ "$(cat "$2/source.txt")" = "$1" ]
out=$3
mkdir -p -- "$out"
touch -- "$out/native.ok"
printf '%s\n' "$2" > "$out/framework.txt"
shift 3
printf '%s\n' "$@" > "$out/argv"
SH
chmod +x "$tmp/bin/cmake" "$tmp/runtime" "$tmp/submission"
first=$tmp/first/TURTLE
second="$tmp/second checkout/TURTLE"
checkout() {
    mkdir -p "$1/tools" "$1/implementations"
    cp -- "$root/bench.sh" "$1/bench.sh"
    cp -R -- "$root/tools/submission-starter" "$1/tools/"
    cp -- "$tmp/submission" "$1/tools/submission-build.sh"
}
run() {
    expected=$1; shift
    rc=0
    (cd "$tmp/caller" && env -i PATH="$tmp/bin:/usr/bin:/bin" TEST_RUNTIME="$tmp/runtime" "$@") > "$tmp/run.log" 2>&1 || rc=$?
    [ "$rc" = "$expected" ]
}
key() {
    hash=$(printf '%s' "$1" | sha256sum)
    printf '%s\n' "${hash%% *}"
}
result() { sed -n "s/^$1: //p" "$tmp/run.log"; }
directory_set() {
    for dir in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        [ ! -d "$dir" ] || printf '%s\n' "${dir##*/}"
    done
}
assert_clean() {
    directory_set "$1" > "$tmp/current-dirs"
    diff -u -- "$1.dirs" "$tmp/current-dirs"
}

checkout "$first"
checkout "$second"
directory_set "$first" > "$first.dirs"
directory_set "$second" > "$second.dirs"
home="$tmp/user home"
cache="$tmp/xdg cache"
data="$tmp/xdg data"
run 0 "$first/bench.sh" --help
run 2 "$first/bench.sh"
grep -Fq 'Missing submission' "$tmp/run.log"
assert_clean "$first"
for tree in "$first" "$second"; do
    touch -- "$tree/implementations/implementation.cpp" "$tree/implementations/build.sh"
    chmod +x "$tree/implementations/build.sh"
done

run 0 HOME="$home" XDG_CACHE_HOME="$cache" XDG_DATA_HOME="$data" "$first/bench.sh" --build-only -- 'a b'
first_job=$(result Results)
case $first_job in "$data"/turtle/runs/submission-????????) ;; *) exit 1;; esac
first_cache=$cache/turtle/$(key "$first")/submission
[ "$(cat "$first_job/build/framework.txt")" = "$first_cache" ]
[ "$(cat "$first_job/build/argv")" = 'a b' ]
assert_clean "$first"

run 0 XDG_CACHE_HOME="$cache" XDG_DATA_HOME="$data" "$second/bench.sh" --build-only
second_job=$(result Results)
second_cache=$cache/turtle/$(key "$second")/submission
[ "$first_job" != "$second_job" ]
[ "$first_cache" != "$second_cache" ]
[ "$(cat "$second_job/build/framework.txt")" = "$second_cache" ]
[ "$(cat "$first_cache/source.txt")" = "$first" ]
[ "$(cat "$second_cache/source.txt")" = "$second" ]
assert_clean "$second"

run 37 HOME="$home" XDG_CACHE_HOME="$cache" XDG_DATA_HOME="$data" TEST_RUNTIME_RC=37 "$first/bench.sh" profile.json
profile=$(result Outputs)
case $profile in "$data"/turtle/runs/run-????????/results) ;; *) exit 1;; esac
grep -Fxq 'profile.json' "$profile/argv"
[ "$(cat "$cache/turtle/$(key "$first")/legacy/source.txt")" = "$first" ]

# Relative and empty XDG paths use the absolute HOME fallback.
run 0 HOME="$home" XDG_CACHE_HOME=relative-cache XDG_DATA_HOME= "$first/bench.sh" --pair
pair=$(result Outputs)
case $pair in "$home"/.local/share/turtle/runs/run-????????/results) ;; *) exit 1;; esac
[ "$(cat "$home/.cache/turtle/$(key "$first")/legacy/source.txt")" = "$first" ]
test ! -e "$tmp/caller/relative-cache"

# Explicit paths are sufficient with no HOME or XDG variables; --out and
# --resume outrank TURTLE_OUTPUT_DIR and the profile's own path does too.
fw="$tmp/custom framework"; base="$tmp/custom results"; job="$tmp/explicit job"
run 0 TURTLE_BUILD_DIR="$fw" TURTLE_OUTPUT_DIR="$base" "$first/bench.sh" --build-only --out "$job"
[ "$(result Results)" = "$job" ]
[ "$(cat "$job/build/framework.txt")" = "$fw" ]
run 0 TURTLE_BUILD_DIR="$fw" "$first/bench.sh" --build-only --resume "$job"
[ "$(result Results)" = "$job" ]
run 0 TURTLE_BUILD_DIR="$fw" TURTLE_OUTPUT_DIR="$base" "$first/bench.sh" profile.json "$tmp/profile result"
[ "$(result Outputs)" = "$tmp/profile result" ]
test ! -e "$base"
run 0 TURTLE_BUILD_DIR="$fw" TURTLE_OUTPUT_DIR="$base" "$first/bench.sh" --build-only
case $(result Results) in "$base"/submission-????????) ;; *) exit 1;; esac
run 0 TURTLE_BUILD_DIR="$fw" TURTLE_OUTPUT_DIR="$base" "$first/bench.sh" --pair
case $(result Outputs) in "$base"/run-????????/results) ;; *) exit 1;; esac

# Refuse a default pointing through a symlink into the checkout, but leave
# intentional explicit paths and the existing submission-slot guard alone.
ln -s -- "$first" "$tmp/checkout-link"
run 2 XDG_CACHE_HOME="$tmp/checkout-link" XDG_DATA_HOME="$data" "$first/bench.sh" --build-only
grep -Fq 'Default storage must be outside the checkout' "$tmp/run.log"
run 2 XDG_DATA_HOME="$tmp/checkout-link" TURTLE_BUILD_DIR="$fw" "$first/bench.sh" profile.json
grep -Fq 'Default storage must be outside the checkout' "$tmp/run.log"
run 2 TURTLE_BUILD_DIR="$fw" "$first/bench.sh" --build-only
grep -Fq 'Set an absolute HOME' "$tmp/run.log"
test ! -e "$first/turtle"
assert_clean "$first"
echo 'PASS: external benchmark defaults, checkout isolation, profile and submission overrides, and early validation'
