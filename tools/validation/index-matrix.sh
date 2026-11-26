#!/bin/sh
# Independent readback of the fixed 20-case validation protocol, not a latency estimator.
set -eu
fail() { echo "invalid measurement archive: $*" >&2; exit 1; }
require_exact_json() {
    jq -en 'all("9007199254740993", "18446744073709551615";
        . as $digits | (fromjson|tostring)==$digits)' >/dev/null ||
        fail 'verified readback needs jq with lossless uint64 JSON literals (decimal-number support)'
}
check_transport_rows() {
    # Raw uint64 fields remain strings; jq arithmetic on full ns values rounds.
    jq -Rse --argjson old "$2" --slurpfile case "$3" --arg phase "$4" \
        --arg id "$5" --arg role "$6" --arg path "$1" '
        def uint64:
            test("^[1-9][0-9]*$") and
            (length < 20 or (length == 20 and . <= "18446744073709551615"));
        # For ordered operands, subtract in two base-10^10 limbs. Each
        # intermediate fits exactly in jq arithmetic; the result is a string.
        def limbs: [("0"+.[0:-10]|tonumber), (.[-10:]|tonumber)];
        def span($start; $end):
            ($start|limbs) as $s | ($end|limbs) as $e
            | ($e[1]-$s[1]) as $low
            | ($e[0]-$s[0]-(if $low<0 then 1 else 0 end)) as $high
            | (($low+10000000000)%10000000000|tostring) as $digits
            | if $high==0 then $digits
              else ($high|tostring) + ("0000000000"+$digits)[-10:] end;
        def same_point($event; $point; $row):
            $point.event==$event[0] and ($point.monotonic_ns|type)=="number" and
            ($point.monotonic_ns|tostring)==$event[1] and ($point.bytes|type)=="number" and
            ($point.bytes|tostring)==$event[2] and $point.role==$role and
            $point.row==$row and $point.layer=="ciphertext_hook" and
            $point.direction==(if $event[0]=="before_send_offer" then "send" else "receive" end);
        split("\n") | select(.[0]=="event,monotonic_ns,bytes" and .[-1]=="") | .[1:-1]
        | map(split(",")) | select(all(.[]; length==3 and
            (.[0]=="before_send_offer" or .[0]=="after_recv") and
            (.[1]|uint64) and (.[2]|uint64))) as $events
        | ($events|length) as $n
        | ($events|map(select(.[0]=="before_send_offer"))|length) as $send
        | ($events|map(.[1])) as $ns
        | select($send>0 and $send<$n and ($ns|sort_by(length,.))==$ns)
        | if $old then $n else
            [$case[0][$phase].evidence[] | select(.connection_id==$id)]
            | select(length==1) | .[0]
            | select(.verified==true and .transport_csv==$path and .transport_count==($path+".count"))
            | .transport | select(.before_send_offers==$send and .after_recv_returns==($n-$send) and
                .send_size_semantics=="requested_write_bytes" and .receive_size_semantics=="positive_return_bytes")
            | .coverage_span | select(.clock=="CLOCK_MONOTONIC" and
                same_point($events[0]; .start; 1) and same_point($events[-1]; .end; $n) and
                (.delta_ns|type)=="number" and (.delta_ns|tostring)==span($ns[0]; $ns[-1]))
            | $n
          end' "$1"
}

# Matrix entry point (the transport reader above is exercised by its CTest fixture).
runtime_only=false
origin=
for _ in 1 2; do
    case "${1-}" in
        --runtime-only) runtime_only=true; shift;;
        --build-from) [ "$#" -ge 2 ] || fail 'missing --build-from job'; origin=$2; shift 2;;
        *) break;;
    esac
done
[ "$#" = 2 ] || { echo 'Usage: index-matrix.sh [--runtime-only] [--build-from BUILD_JOB] RUN NEW_INDEX' >&2; exit 2; }
if ! "$runtime_only"; then require_exact_json; fi
job=$(realpath -e -- "$1")
sum=$job/summary.json
b=$job/build
if [ -n "$origin" ]; then
    origin=$(realpath -e -- "$origin")
    b=$origin/build
    here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
    sh "$here/submission-receipt.sh" verify "$b"
    jq -e --arg b "$b" '.build_directory == $b' "$sum" >/dev/null ||
        fail 'recorded build directory differs from --build-from'
else
    jq -e --arg b "$b" '(.build_directory // $b) == $b' "$sum" >/dev/null ||
        fail 'selected build lives separately; pass --build-from BUILD_JOB'
fi
observer=$(jq -r '.observer_path // empty' "$sum")
if [ -n "$observer" ]; then
    [ "$observer" = "$b/runtime/libturtle_observe.so.1" ] && [ -f "$observer" ] &&
        [ ! -L "$observer" ] || fail 'unexpected or unavailable job-local observer'
    digest=$(sha256sum < "$observer")
    jq -e --arg digest "${digest%% *}" '.observer_sha256 == $digest' "$sum" >/dev/null ||
        fail 'job-local observer digest differs from selected report'
elif [ -n "$origin" ]; then
    fail 'reused report has no job-local observer receipt'
fi
out=$(realpath -m -- "$2"); mkdir -- "$out"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
absent() { [ ! -e "$1" ] && [ ! -L "$1" ] || fail "unexpected artifact: $1"; }
(cd "$b" && sha256sum -c expected-libs.sha256) > "$out/library-check.log"
printf 'auth\tscenario\ttarget\tphase\tpurpose\tconnection_id\tport\tclient_pid\tserver_pid\ttrace_rows\tclient_sent\tserver_sent\tqualified\tattempt\ttrace\n' > "$out/connections.tsv"
printf 'auth\tscenario\ttarget\truntime_successes\tverified_samples\trequested\tstate\tcase_directory\n' > "$out/cases.tsv"
jq -e '.cases|length==20' "$sum" >/dev/null
for auth in server mtls; do for s in S0 S1 S2 S3 S4; do for role in client server; do
    base="runs/$auth-$s-$role"
    peer=server; [ "$role" = client ] || peer=client
    jq -e --arg a "$auth" --arg s "$s" --arg r "$role" \
        '[.cases[]|select(.auth==$a and .scenario==$s and .role==$r)]|select(length==1)|.[0]' "$sum" > "$tmp/case"
    for phase in doctor benchmark; do
        d=$job/$base/$phase
        report=$d/result/analysis.json
        if ! "$runtime_only"; then
            partial=$(find "$d/events" -name '*.partial' -print -quit) || fail "cannot inspect events: $d"
            [ -z "$partial" ] || fail "unfinished evidence: $partial"
        fi
        # Doctor is a separate one-connection controller run whose local purpose is "sample".
        jq -e --arg p "$phase" '.complete and ([.attempts[].purpose] ==
          (if $p=="doctor" then ["sample"] else ["warmup","sample","sample"] end))' "$report" >/dev/null
        jq -e --arg a "$auth" --arg s "$s" --arg r "$role" --arg peer "$peer" --arg bin "$b/bin/" \
          '.profile | .auth==$a and .scenario==$s and .target.role==$r and .target.argv[0]==($bin+$r)
           and .target.argv[-1]=="measured" and .peer.argv[0]==($bin+$peer) and .peer.argv[-1]=="peer"
           and (.scenario!="S4" or .application.greeting!=.application.response)' "$d/result/manifest.json" >/dev/null
        jq -j --arg s "$s" 'if (["S1","S3","S4"]|index($s))!=null then .profile.application.request else "" end' "$d/result/manifest.json" > "$tmp/cad"
        jq -j --arg s "$s" '.profile.application | (if (["S2","S4"]|index($s))!=null then .greeting else "" end)
              + (if (["S3","S4"]|index($s))!=null then .response else "" end)' "$d/result/manifest.json" > "$tmp/sad"
        jq -r '.attempts[] | select(.task_success==true) | [.connection_id,.directory,.purpose,.qualified]|@tsv' "$report" > "$tmp/attempts"
        while IFS="$(printf '\t')" read -r id attempt purpose qualified; do
            case $attempt in attempt-[0-9]*) ;; *) fail "$attempt";; esac
            raw=$d/result/$attempt
            jq -e --arg id "$id" --arg r "$role" --arg p "$peer" --arg bin "$b/bin/" \
              '.connection_id==$id and .exit=={"client":0,"server":0} and .error==null and .pid.client!=.pid.server
               and .argv[$r][0]==($bin+$r) and .argv[$r][-1]=="measured" and .argv[$p][0]==($bin+$p) and .argv[$p][-1]=="peer"' \
              "$raw/attempt.json" >/dev/null
            cmp "$tmp/cad" "$raw/client.stdin"; cmp "$tmp/cad" "$raw/server.stdout"
            cmp "$tmp/sad" "$raw/server.stdin"; cmp "$tmp/sad" "$raw/client.stdout"
            trace="$base/$phase/events/$id.$role.csv"
            absent "$d/events/$id.$peer.csv"
            if ! "$runtime_only"; then absent "$d/events/$id.$peer.csv.count"; fi
            for side in client server; do
                snapshot="$d/events/$id.$side.maps"
                if ! "$runtime_only"; then
                    count=$(wc -l < "$snapshot") || fail "unreadable maps: $snapshot"
                    [ "$count" -gt 1 ] || fail "empty maps: $snapshot"
                    printf '# turtle-maps rows=%s\n' "$((count-1))" > "$tmp/maps-end"
                    tail -n 1 -- "$snapshot" | cmp -s - "$tmp/maps-end" ||
                        fail "incomplete maps: $snapshot"
                fi
                sed -n 's|^[^/]*\(/.*\)$|\1|p' "$snapshot" > "$tmp/maps"
                grep -Fxq -- "$b/bin/$side" "$tmp/maps"
                if [ -n "$observer" ]; then grep -Fxq -- "$observer" "$tmp/maps"; fi
                while IFS= read -r lib; do grep -Fxq -- "$lib" "$tmp/maps"; done < "$b/expected-libs.txt"
            done
            jq -e -s --arg id "$id" --arg p "$peer" --slurpfile attempt "$raw/attempt.json" '
              length>0 and all(.[]; .connection_id==$id and .role==$p and .pmu?==null) and
              (if .[0].v==2 then
                . as $rows | (length-1) as $n |
                $n>0 and .[-1].kind=="observer_complete" and .[-1].count==$n and
                all(.[]; .v==2 and .run_id==$attempt[0].run_id and .pid==$attempt[0].pid[$p]) and
                all(range(0; $n); . as $i | $rows[$i] |
                    .seq==($i+1) and .kind!="observer_complete" and .kind!="observer_loss")
              else all(.[]; .v==1 and .kind!="observer_complete" and .kind!="observer_loss") end)' \
              "$raw/$peer.ndjson" >/dev/null
            # Offers are requested writes, not syscall completions. Check raw
            # endpoints and span against the same connection's evaluated trace.
            rows=$(check_transport_rows "$job/$trace" "$runtime_only" "$tmp/case" "$phase" "$id" "$role") ||
                fail "invalid hook rows or summary mismatch: $trace"
            if ! "$runtime_only"; then
                printf '%s\n' "$rows" | cmp -s - "$job/$trace.count" ||
                    fail "missing or inconsistent producer hook count: $trace.count"
            fi
            [ "$phase" != doctor ] || purpose=doctor
            fields=$(jq -r '[.port,.pid.client,.pid.server]|@tsv' "$raw/attempt.json")
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
              "$auth" "$s" "$role" "$phase" "$purpose" "$id" "$fields" "$rows" \
              "$(wc -c < "$tmp/cad")" "$(wc -c < "$tmp/sad")" "$qualified" "$base/$phase/result/$attempt" "$trace" >> "$out/connections.tsv"
        done < "$tmp/attempts"
    done
    # An old verified_samples only establishes the historical, weaker runtime gate.
    verdict=$(jq -r --argjson old "$runtime_only" '[.benchmark.task_successes,
      (if $old then "-" else .benchmark.verified_samples end),2,
      (if $old then "runtime_only" else .state end)] | @tsv' "$tmp/case")
    printf '%s\t%s\t%s\t%s\t%s\n' "$auth" "$s" "$role" "$verdict" "$base" >> "$out/cases.tsv"
done; done; done
tail -n +2 "$out/connections.tsv" | cut -f6 | sort -u > "$tmp/ids"
test "$(wc -l < "$tmp/ids")" -eq 80 || fail 'expected 80 different connection IDs'
for entry in doctor:20 warmup:20 sample:40; do
    n=$(cut -f5 "$out/connections.tsv" | grep -c "^${entry%:*}\$" || :)
    test "$n" = "${entry#*:}" || fail "incorrect phase count: $entry got $n"
done
if ! "$runtime_only"; then
    jq -e '.complete and .library_hash_check=="matched_before_and_after_run" and
        all(.cases[]; .state=="passed" and .doctor.verified_connections==1 and .doctor.verified_samples==0 and
        .benchmark.verified_samples==2)' "$sum" >/dev/null
fi
echo '80 unique connections; 20 doctor, 20 warmup, 40 samples; both maps, peer exclusion, raw hooked I/O and exact transcripts checked.'
