#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
verify() {
    job=$(realpath -e -- "$1")
    [ "$(cat "$job/build/native.exit")" = 0 ]
    [ -s "$job/build/implementation.d" ]; [ -s "$job/build/client.map" ]; [ -s "$job/build/server.map" ]
    sha256sum --quiet -c "$job/build/expected-libs.sha256"
    jq -e '.runtime_complete and (.cases | length == 1) and
        (.cases[0] | .role == "client" and .auth == "server" and .scenario == "S3" and
         .doctor.ready and .doctor.verified_samples == 0 and
         ([.doctor.evidence[].purpose] == ["doctor"]) and
         .benchmark.ready and .benchmark.runtime_verified_samples == 2 and
         (if .state == "passed" then .benchmark.verified_samples == 2
          else .state == "insufficient_evidence" and .benchmark.verified_samples < 2 end) and
         ([.benchmark.evidence[].purpose] == ["warmup","sample","sample"]))' "$job/summary.json" >/dev/null
    path=$job/runs/server-S3-client
    for phase in doctor benchmark; do
        d=$path/$phase
        jq -e --arg root "$job/build/bin/" '.target.argv[0] == ($root+"client") and .target.argv[-1] == "measured" and
            .peer.argv[0] == ($root+"server") and .peer.argv[-1] == "peer"' "$d/profile.json" >/dev/null
        jq -er '.attempts[].connection_id' "$d/result/analysis.json" > "$tmp/ids"
        while IFS= read -r id; do
            test ! -e "$d/events/$id.server.csv"
            grep -q '^before_send_offer,' "$d/events/$id.client.csv"
            grep -q '^after_recv,' "$d/events/$id.client.csv"
            for side in client server; do
                maps=$d/events/$id.$side.maps
                grep -Fq -- "$job/build/bin/$side" "$maps"
                while IFS= read -r lib; do grep -Fq -- "$lib" "$maps"; done < "$job/build/expected-libs.txt"
            done
        done < "$tmp/ids"
    done
}
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
case ${1-} in
    --check-default) verify "$2";;
    --live)
        rc=0; "$root/bench.sh" --out "$tmp/job" || rc=$?
        verify "$tmp/job"
        if jq -e '.complete' "$tmp/job/summary.json" >/dev/null; then
            [ "$rc" = 0 ]
        else
            [ "$rc" = 1 ]
        fi;;
    --recipe-failure)
        t=$tmp/TURTLE
        mkdir -p "$t/implementations/native"
        cp "$root/bench.sh" "$root/CMakeLists.txt" "$t/"
        cp -R "$root/src" "$root/tools" "$t/"
        mkdir "$t/docs"; cp -R "$root/docs/examples" "$t/docs/"
        if [ -d "$root/.deps" ]; then ln -s "$root/.deps" "$t/.deps"; fi
        : > "$t/implementations/implementation.cpp"
        printf '%s\n' '#!/bin/sh' 'set -eu' '[ -d ./native ] && [ -d "$1" ] && [ -d "$2" ] && [ "$3" = "word with spaces" ] || exit 70' 'echo entered-native-recipe' 'exit 23' > "$t/implementations/build.sh"
        chmod +x "$t/implementations/build.sh"
        rc=0; (cd / && TURTLE_BUILD_DIR="$t/build" "$t/bench.sh" --out "$tmp/job" -- 'word with spaces') > "$tmp/log" 2>&1 || rc=$?
        if [ "$rc" -ne 23 ]; then cat "$tmp/log"; exit 1; fi
        [ "$(cat "$tmp/job/build/native.exit")" = 23 ]
        grep -Fxq entered-native-recipe "$tmp/job/build/native.log"
        [ ! -e "$tmp/job/build/bin" ]; [ ! -e "$tmp/job/runs" ]; [ ! -e "$tmp/job/summary.json" ]
        printf '%s\n' 'root -> native recipe: cwd, native work/prefix, exact argv; exit 23 propagated, no roles or benchmark launched';;
    '')
        cp "$root/bench.sh" "$tmp/"
        "$tmp/bench.sh" --help | grep -q 'implementations/build.sh'
        rc=0; (cd / && "$tmp/bench.sh") > "$tmp/log" 2>&1 || rc=$?
        [ "$rc" = 2 ]; grep -q 'Missing submission' "$tmp/log"
        [ ! -d "$tmp/build" ]; [ ! -d "$tmp/outputs" ];;
    *) exit 2;;
esac
