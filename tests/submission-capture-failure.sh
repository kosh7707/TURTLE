#!/bin/sh
# Real role and job processes, real OpenSSL TLS, explicit evidence failures.
set -eu
controller=$1 runner=$2 bridge=$3 client=$4 server=$5
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
job=$tmp/job
mkdir -p "$job/build/bin" "$job/build/prefix/lib"
lib=$job/build/prefix/lib/${bridge##*/}
cp -- "$bridge" "$lib"
cp -- "$client" "$job/build/bin/client"
cp -- "$server" "$job/build/bin/server"
printf '%s\n' "$lib" > "$job/build/expected-libs.txt"
sha256sum -- "$lib" > "$job/build/expected-libs.sha256"
unset LD_PRELOAD LD_AUDIT
LD_LIBRARY_PATH=$job/build/prefix/lib
export LD_LIBRARY_PATH
check() {
    if ! jq -e "$1" "$job/summary.json" >/dev/null; then
        jq '.cases[0] | {state, doctor: (.doctor | {state,ready,task_successes,connection:.evidence[0]})}' "$job/summary.json" >&2
        cat -- "$job/runs/server-S0-client/doctor/result/attempt-1/client.stderr" >&2
        exit 1
    fi
}
d=$job/runs/server-S0-client/doctor
TURTLE_TEST_EVENTS=$d/events
export TURTLE_TEST_EVENTS
for fault in missing overflow detach trace-write count-write maps error unsupported healthy; do
    rc=0
    TURTLE_TEST_HOOK_FAULT=$fault "$runner" "$controller" "$job" client S0 server 0 1 "" \
        > "$tmp/$fault.log" 2>&1 || rc=$?
    want=1
    [ "$fault" != healthy ] || want=0
    [ "$rc" = "$want" ] || { cat "$tmp/$fault.log" >&2; exit 1; }
    case $fault in
        missing|overflow|detach|trace-write|count-write|maps)
            check '.cases[0] | .state=="insufficient_evidence" and (.doctor |
                   .task_successes==1 and .verified_connections==0 and
                   (.evidence[0] | .state=="insufficient_evidence" and .endpoint_results=={"client":0,"server":0}
                         and .role_stderr.client != null))'
            reason='transport hooks were not observed'
            [ "$fault" != overflow ] || reason='transport trace incomplete'
            [ "$fault" != detach ] || reason='could not detach transport hooks'
            [ "$fault" != trace-write ] || reason='could not write transport trace'
            [ "$fault" != count-write ] || reason='could not write transport count'
            [ "$fault" != maps ] || reason='could not record process maps'
            grep -Fq -- "$reason" "$d/result/attempt-1/client.stderr"
            test -n "$(find "$d/events" -name '*.server.maps' -print)"
            if [ "$fault" = maps ]; then
                test -z "$(find "$d/events" -name '*.client.maps' -print)"
                check '.cases[0].doctor.evidence[0].transport.coverage_span.delta_ns>=0'
            elif [ "$fault" = count-write ]; then
                test -n "$(find "$d/events" -name '*.client.csv' -print)"
                test -z "$(find "$d/events" -name '*.csv.count' -print)"
                check '.cases[0].doctor.evidence[0].transport==null'
            else
                test -n "$(find "$d/events" -name '*.client.maps' -print)"
                test -z "$(find "$d/events" -name '*.csv' -print)"
                check '.cases[0].doctor.evidence[0].transport==null'
            fi
            if [ "$fault" = overflow ]; then
                partial=$(find "$d/events" -name '*.csv.partial' -print)
                grep -q '^before_send_offer,' "$partial"
                grep -q '^after_recv,' "$partial"
            fi;;
        error) check '.cases[0] | .state=="failed" and .doctor.task_successes==0';;
        unsupported) check '.cases[0] | .state=="unsupported" and .doctor.task_successes==0';;
        healthy)
            check '.complete and (.cases[0] |
                   .doctor.verified_connections==1 and .benchmark.verified_samples==1 and
                   all(.doctor.evidence[], .benchmark.evidence[];
                       (.prepared_images | keys == ["client","server"]) and
                       all(.prepared_images[]; .state=="matched" or .state=="unavailable") and
                       .transport_count==(.transport_csv+".count") and
                       .peer_transport_trace_absent))'
            test -z "$(find "$job/runs" -name '*.partial' -print)";;
    esac
    mv -- "$job/summary.json" "$tmp/$fault.json"
    mv -- "$job/runs" "$tmp/runs-$fault"
done
echo 'PASS: post-task capture faults are insufficient; installation failure and unsupported remain distinct'

# Modify only the report inputs after the real TLS controller returns but
# before the job aggregates them. A valid CSV prefix is not a complete capture.
cat > "$tmp/controller" <<'EOF'
#!/bin/sh
set -eu
"$TURTLE_TEST_REAL_CONTROLLER" "$@"
set -- "${3%/*}"/events/*.client.csv
test "$#" = 1 && test -f "$1"
csv=$1
count=$csv.count
case "$TURTLE_TEST_TRACE_LOSS" in
    last|middle)
        mv -- "$csv" "$csv.full"
        if [ "$TURTLE_TEST_TRACE_LOSS" = last ]; then
            sed '$d' "$csv.full" > "$csv"
        else
            sed '3d' "$csv.full" > "$csv"
        fi
        grep -q '^before_send_offer,' "$csv"
        grep -q '^after_recv,' "$csv"
        test "$(wc -l < "$csv")" -eq "$(($(wc -l < "$csv.full") - 1))";;
    no-count) rm -f -- "$count";;
    malformed-count) printf '15\n16\n' > "$count";;
    unterminated-count) printf '15' > "$count";;
    partial-count) mv -- "$count" "$count.partial";;
    partial-csv) : > "$csv.partial";;
    extra-peer-count) cp -- "$count" "${csv%.client.csv}.server.csv.count";;
esac
EOF
chmod 700 "$tmp/controller"
TURTLE_TEST_REAL_CONTROLLER=$controller
export TURTLE_TEST_REAL_CONTROLLER
for loss in last middle no-count malformed-count unterminated-count partial-count partial-csv extra-peer-count; do
    rc=0
    TURTLE_TEST_HOOK_FAULT=healthy TURTLE_TEST_TRACE_LOSS=$loss \
        "$runner" "$tmp/controller" "$job" client S0 server 0 1 "" \
        > "$tmp/$loss.log" 2>&1 || rc=$?
    state=insufficient_evidence
    [ "$loss" != extra-peer-count ] || state=failed
    if [ "$rc" != 1 ]; then
        echo "$loss: expected evidence rejection; job exit $rc" >&2
        jq -c '.cases[0].doctor.evidence[0] | {state,endpoint_results,transport}' "$job/summary.json" >&2
        exit 1
    fi
    check ".cases[0] | .state==\"$state\" and (.doctor |
           .task_successes==1 and .verified_connections==0 and
           (.evidence[0] | .state==\"$state\" and .endpoint_results=={\"client\":0,\"server\":0}))"
    if [ "$loss" != extra-peer-count ]; then
        check '.cases[0].doctor.evidence[0].transport==null'
    fi
    echo "$loss: $state; both TLS endpoints exit 0"
    mv -- "$job/summary.json" "$tmp/$loss.json"
    mv -- "$job/runs" "$tmp/runs-$loss"
done
