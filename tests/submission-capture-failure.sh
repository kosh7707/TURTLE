#!/bin/sh
# Real role and job processes, real OpenSSL TLS, explicit evidence failures.
set -eu
controller=$1 runner=$2 bridge=$3 client=$4 server=$5
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
job=$tmp/job
mkdir -p "$job/build/bin" "$job/build/prefix/lib" "$job/build/runtime"
cp -L -- "$(dirname "$controller")/libturtle_observe.so.1" "$job/build/runtime/"
lib=$job/build/prefix/lib/${bridge##*/}
cp -- "$bridge" "$lib"
cp -- "$client" "$job/build/bin/client"
cp -- "$server" "$job/build/bin/server"
printf '%s\n' "$lib" > "$job/build/expected-libs.txt"
sha256sum -- "$lib" > "$job/build/expected-libs.sha256"
unset LD_PRELOAD LD_AUDIT
LD_LIBRARY_PATH=$job/build/runtime:$job/build/prefix/lib
export LD_LIBRARY_PATH
# This test drives the job at its internal ABI, without a sealed bench build.
receipt_check=$tmp/check-receipt
cat > "$receipt_check" <<'EOF'
#!/bin/sh
test "$1" = verify && test -f "$2/expected-libs.sha256"
EOF
check() {
    if ! jq -e "$1" "$job/summary.json" >/dev/null; then
        jq '.cases[0] | {state, doctor: (.doctor | {state,ready,task_successes,connection:.evidence[0]})}' "$job/summary.json" >&2
        cat -- "$job/runs/server-S0-client/doctor/result/attempt-1/client.stderr" >&2
        exit 1
    fi
}
if [ "${6-}" = --phase-readback ]; then
    # One real S4/mTLS sample gives the finalized row its true event shape;
    # repeat the artifacts, not the handshake, for the large consumer test.
    cat >"$tmp/controller" <<'SH'
#!/bin/sh
set -eu
root=$3
case "$root" in
    */doctor/result) exec "$TURTLE_TEST_REAL_CONTROLLER" "$@";;
esac
if [ "$TURTLE_TEST_READBACK" = large ]; then
    fixture=$root.single
    jq '.repetitions=1' "$2" >"${2%.json}.single.json"
    "$TURTLE_TEST_REAL_CONTROLLER" run "${2%.json}.single.json" "$fixture"
    first=$fixture/attempt-1
    n=$(jq -r '.repetitions' "$2")
    values=$(jq '[paths] | length' "$first/analysis.json")
    test "$((values * n))" -gt 2000000
    old=$(jq -r '.connection_id' "$first/analysis.json")
    events=${root%/*}/events
    mkdir "$root"
    # Stream a legacy diagnostic aggregate with the same finalized row bodies.
    jq -cnr --slurpfile row "$first/analysis.json" --slurpfile raw "$first/attempt.json" \
        --argjson n "$n" '
        range(1; $n+1) as $i | ($i | tostring) as $s |
        ("70000000-0000-4000-8000-" + ("000000000000"+$s)[-12:]) as $id |
        ("attempt-"+$s) as $dir |
        [$dir, $id, ($row[0]+{directory:$dir,connection_id:$id}|tojson),
             ($raw[0]+{connection_id:$id}|tojson)] | join("\t")' >"$fixture/rows"
    tab=$(printf '\t')
    {
        jq -c --argjson n "$n" 'del(.attempts) |
            .successful_measurements=$n | .qualified_samples *= $n |
            .eligible_measurements=.qualified_samples | .measurement_count=$n |
            .samples=$n' "$fixture/analysis.json" | sed 's/}$/,"attempts":[/'
        sep=
        while IFS="$tab" read -r name id row raw; do
            mkdir "$root/$name"
            printf '%s\n' "$raw" >"$root/$name/attempt.json"
            printf '%s\n' "$row" >"$root/$name/analysis.json"
            for event in "$events/$old".*; do
                suffix=${event##*/}
                ln "$event" "$events/$id.${suffix#"$old".}"
            done
            printf '%s%s\n' "$sep" "$row"
            sep=,
        done <"$fixture/rows"
        printf ']}\n'
    } >"$root/analysis.json"
    jq --argjson n "$n" '.repetitions=$n | .attempt_count=$n |
        .successful_measurements=$n | .qualified_samples *= $n' \
        "$fixture/analysis-summary.json" >"$root/analysis-summary.json"
else
    "$TURTLE_TEST_REAL_CONTROLLER" "$@"
    case "$TURTLE_TEST_READBACK" in
        missing) rm -- "$root/attempt-1/analysis.json";;
        malformed) printf '{' >"$root/attempt-1/analysis.json";;
        invalid-value)
            jq '.benchmark_timing_ns="not a duration"' "$root/attempt-1/analysis.json" >"$root/altered.json"
            mv -- "$root/altered.json" "$root/attempt-1/analysis.json";;
        tallies)
            jq '.successful_measurements=1 | .qualified_samples=0' "$root/analysis-summary.json" >"$root/altered.json"
            mv -- "$root/altered.json" "$root/analysis-summary.json";;
        symlink)
            mv -- "$root/attempt-1" "$root/outside-attempt"
            ln -s "$root/outside-attempt" "$root/attempt-1";;
        identity)
            jq '.run_id="another-run"' "$root/attempt-1/attempt.json" >"$root/altered.json"
            mv -- "$root/altered.json" "$root/attempt-1/attempt.json";;
        no-summary) rm -- "$root/analysis-summary.json";;
        global)
            # Replay fails inventory verification even though stale finalized
            # rows exist. The job must honor the global report's error.
            printf 'bad inventory\n' >>"$root/attempt-1/client.stderr"
            exec "$TURTLE_TEST_REAL_CONTROLLER" analyze "$root";;
    esac
fi
SH
    chmod 700 "$tmp/controller"
    TURTLE_TEST_REAL_CONTROLLER=$controller
    export TURTLE_TEST_REAL_CONTROLLER
    for mode in large missing malformed invalid-value symlink identity no-summary tallies global; do
        want=1 count=2
        if [ "$mode" = large ]; then want=0 count=720; fi
        rc=0
        TURTLE_TEST_HOOK_FAULT=healthy TURTLE_TEST_READBACK=$mode \
            "$runner" "$tmp/controller" "$job" client S4 mtls 0 "$count" "" \
                "$job/build" "$receipt_check" >"$tmp/$mode.log" 2>&1 || rc=$?
        [ "$rc" = "$want" ] || { cat "$tmp/$mode.log" >&2; exit 1; }
        case "$mode" in
            large)
                [ "$(wc -l <"$job/results.csv")" -eq "$((count+2))" ]
                grep -q "^mtls,S4,client,passed,$count,$count,$count," "$job/cases.csv"
                test "$(cut -d, -f5 "$job/results.csv" | sort -u | wc -l)" -eq "$((count+2))"
                check '.complete and (.cases[0] |
                     .doctor.verified_samples == 0 and .doctor.verified_connections == 1 and
                     .benchmark.task_successes == 720 and .benchmark.verified_samples == 720)'
                ;;
            no-summary|tallies|global)
                [ "$(wc -l <"$job/results.csv")" -eq 2 ]
                case "$mode" in
                    no-summary) reason='controller produced no valid analysis-summary.json';;
                    tallies) reason='finalized rows disagree with controller analysis summary';;
                    global) reason='invalid_attempt_inventory';;
                esac
                grep -q "$reason" "$job/cases.csv"
                ;;
            *)
                [ "$(wc -l <"$job/results.csv")" -eq 3 ]
                grep -q '^mtls,S4,client,insufficient_evidence,2,1,1,' "$job/cases.csv"
                check '(.runtime_complete|not) and (.cases[0].benchmark |
                    .task_successes == 1 and (.evidence|length) == 1 and
                    (.reason | startswith("attempt-1:")))'
                ;;
        esac
        echo "PASS phase readback: $mode (exit $rc)"
        mv -- "$job/runs" "$tmp/runs-$mode"
    done
    exit 0
fi

d=$job/runs/server-S0-client/doctor
TURTLE_TEST_EVENTS=$d/events
export TURTLE_TEST_EVENTS
for fault in missing overflow detach trace-write count-write maps error unsupported healthy; do
    rc=0
    TURTLE_TEST_HOOK_FAULT=$fault "$runner" "$controller" "$job" client S0 server 0 1 "" "$job/build" "$receipt_check" \
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

# OpenSSL uses the same installed hook bundle for CSV offers/positive receive
# returns and paired actual BIO I/O. Offers, failed returns, a peer's events,
# and a partial/off-owner trace must not qualify a measured source.
for observation in healthy legacy failed-send-observation foreign-thread; do
    rc=0
    TURTLE_TEST_HOOK_FAULT=$observation "$runner" "$controller" "$job" client S0 server 0 1 "" "$job/build" "$receipt_check" \
        > "$tmp/observe-$observation.log" 2>&1 || rc=$?
    saved=$job/runs/server-S0-client/benchmark/result
    if [ "$observation" = foreign-thread ]; then
        test "$rc" = 1 || { cat "$tmp/observe-$observation.log" >&2; exit 1; }
        check '.cases[0] | .state == "insufficient_evidence" and .doctor.task_successes == 1
               and .doctor.evidence[0].endpoint_results == {"client":0,"server":0}'
        saved=$job/runs/server-S0-client/doctor/result
    else
        test "$rc" = 0 || { cat "$tmp/observe-$observation.log" >&2; exit 1; }
        check '.cases[0] | .state == "passed" and .benchmark.verified_samples == 1'
    fi
    case $observation in
        healthy) reason=null;;
        legacy) reason=hook_unobserved;;
        failed-send-observation) reason=no_bidirectional_transfer;;
        foreign-thread) reason=incomplete_transport_capture;;
    esac
    jq -e --arg reason "$reason" 'all(.attempts[];
        .task_success and
        (if $reason == "null" then
            .measured_transport_hook | .verified == true and .source == "library_io"
         else
            .measured_transport_hook | .verified != true and .reason == $reason
         end))' "$saved/analysis.json" >/dev/null
    jq -se 'length > 0 and all(.[]; .role == "server" and .pmu == null and
               (.kind != "io" and .kind != "coverage"))' \
        "$saved/attempt-1/server.ndjson" >/dev/null
    if [ "$observation" = healthy ]; then
        if [ -L /proc/self/ns/time ]; then
            jq -e '.time_namespaces | all(.client, .server; type == "string" and startswith("time:["))' \
                "$saved/attempt-1/attempt.json" >/dev/null
        fi
        jq -se 'map(select(.kind == "io" and .result > 0)) |
            any(.[]; .sent) and any(.[]; .sent == false) and
            all(.[]; .result <= .requested and (.hex | length) == (.result * 2)
                     and .begin_ns <= .ns and .begin_tid == .tid and .pmu == null)' \
            "$saved/attempt-1/client.ndjson" >/dev/null
    fi
    mv -- "$job/runs" "$tmp/runs-observe-$observation"
done
echo 'PASS: actual bidirectional BIO returns qualify; offers, failed sends, peer and foreign-thread evidence do not'

# Verify both socket settings on real connected roles and read the default
# trial outputs as ordinary CSV, without a JSON reader.
unset TURTLE_TEST_EVENTS
for policy in on off; do
    TURTLE_TCP_NODELAY=$policy TURTLE_TEST_HOOK_FAULT=healthy \
        "$runner" "$controller" "$job" client S0 server 1 1 "" "$job/build" "$receipt_check" > "$tmp/csv-$policy.log" 2>&1
    case $policy in on) effective=1;; off) effective=0;; esac
    # Test only the schema's fixed identifier/number fields here; reasons and
    # paths beyond that prefix may be quoted. The fixture uses safe names.
    cut -d, -f1-16 "$job/results.csv" > "$tmp/csv-prefix"
    doctor=0 warmup=0 sample=0
    {
        IFS= read -r header
        [ "$header" = 'auth,scenario,role,purpose,connection_id,task_success,evidence_state,wall_ns,wall_status,first_greeting_read_ns,cycles,pmu_status,performance_qualified,qualification_reason,client_tcp_nodelay,server_tcp_nodelay' ]
        while IFS=, read -r auth scenario role purpose id task evidence wall wall_status first_ns cycles pmu qualified qualification client_socket server_socket; do
            [ "$auth:$scenario:$role:$task:$evidence:$wall_status" = server:S0:client:true:passed:available ]
            [ "$client_socket:$server_socket" = "$effective:$effective" ]
            case $wall in ''|*[!0-9]*) exit 1;; esac
            case $purpose in
                doctor) doctor=$((doctor+1));;
                warmup) warmup=$((warmup+1));;
                sample) sample=$((sample+1));;
                *) exit 1;;
            esac
        done
    } < "$tmp/csv-prefix"
    [ "$doctor:$warmup:$sample" = '1:1:1' ]
    [ "$(cut -d, -f1-6 "$job/cases.csv")" = "$(printf '%s\n' 'auth,scenario,role,state,requested,verified' 'server,S0,client,passed,1,1')" ]
    mv -- "$job/runs" "$tmp/runs-csv-$policy"
done
unset TURTLE_TCP_NODELAY
TURTLE_TEST_EVENTS=$d/events
export TURTLE_TEST_EVENTS
echo 'PASS: on/off receipt for both roles and usable CSV separation of doctor, warmup and sample'


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
        "$runner" "$tmp/controller" "$job" client S0 server 0 1 "" "$job/build" "$receipt_check" \
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
