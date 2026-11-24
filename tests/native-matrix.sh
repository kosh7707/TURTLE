#!/bin/sh
# Explicit release gate: no substitution/skip when the independent CLI or
# same-thread hardware counters are unavailable. Does not install anything.
# Usage: native-matrix.sh RELEASE_BUILD STOCK_GNUTLS_CLI NEW_RESULTS_DIRECTORY
set -eu
export LC_ALL=C
build=$(cd "${1:?release build}" && pwd)
cli=$(realpath "${2:?unmodified gnutls-cli path}")
work=$(realpath -m "${3:?new results directory}")
src=$(cd "$(dirname "$0")" && pwd)/fixtures/generic-line-app.cpp
mkdir "$work"
pkg-config --modversion gnutls >"$work/gnutls-library-version"
"$cli" --version >"$work/stock-version"
cmake --install "$build" --prefix "$work/sdk" >"$work/install.log"
find "$work/sdk" -type f -print0 | sort -z | xargs -0 sha256sum >"$work/frozen.sha256"
sha256sum "$cli" >>"$work/frozen.sha256"
# Post-freeze builds; use installed includes/libs only. The unobserved app
# must work with no TURTLE include or link dependency.
cp "$src" "$work/chat.cpp"
CXX=${CXX:-c++}
lib=$(dirname "$(find "$work/sdk" -name libturtle_observe.so -print -quit)")
"$CXX" -std=c++20 -O2 -Wall -Wextra -Werror "$work/chat.cpp" $(pkg-config --cflags --libs gnutls) -o "$work/chat-no-sdk"
"$CXX" -std=c++20 -O2 -Wall -Wextra -Werror -DOBSERVE "$work/chat.cpp" $(pkg-config --cflags --libs gnutls) \
    -I"$work/sdk/include" -L"$lib" -Wl,-rpath,"$lib" -lturtle_observe -o "$work/chat"
sha256sum "$work/chat.cpp" "$work/chat" "$work/chat-no-sdk" >"$work/apps.sha256"
ldd "$work/chat" >"$work/chat.ldd"
ldd "$work/chat-no-sdk" >"$work/chat-no-sdk.ldd"
if grep -q turtle "$work/chat-no-sdk.ldd"; then echo 'unobserved app linked SDK' >&2; exit 1; fi
turtle="$work/sdk/bin/turtle"
failed=0
reject() { echo "FAIL: $*" >&2; failed=1; }
cell() {
    kind=$1 role=$2 auth=$3 scenario=$4 exe=$5
    name="$kind-$role-$auth-$scenario"
    profile="$work/$name.json"
    out="$work/$name"
    if [ "$kind" = stock ] || [ "$kind" = wrong-name ]; then
        argv=$(jq -cn --arg exe "$exe" --arg auth "$auth" --arg kind "$kind" '[$exe,"--logfile=/dev/stderr","--priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519", "--x509cafile={ca}","--port={port}",(if $kind=="wrong-name" then "--verify-hostname=invalid.example" else "--verify-hostname={peer_name}" end)] + (if $auth=="mtls" then ["--x509certfile={cert}","--x509keyfile={key}"] else [] end) + ["{host}"]')
    else
        argv=$(jq -cn --arg exe "$exe" --arg role "$role" '[$exe,$role,"{host}","{port}","{ca}","{cert}","{key}","{peer_name}"]')
    fi
    jq -n --arg role "$role" --arg auth "$auth" --arg s "$scenario" --argjson argv "$argv" \
        '{v:1,target:{role:$role,argv:$argv},scenario:$s,auth:$auth,expected:{group:"X25519"},timeout_seconds:5,warmups:0,repetitions:2,recording:"detailed",application:{request:"PING/1\n",greeting:"HELLO/1\n",response:"PONG/1\n"}}' >"$profile"
    if [ "$kind" = native-pair ]; then
        other=server; [ "$role" = client ] || other=client
        jq --arg other "$other" --arg exe "$exe" '.peer.argv=[$exe,$other,"{host}","{port}","{ca}","{cert}","{key}","{peer_name}"]|.required_metrics=["tls_flights"]' "$profile" >"$profile.tmp"
        mv "$profile.tmp" "$profile"
    fi
    # Failures (e.g. late server-first) must still have complete raw trials.
    rc=0; "$turtle" run "$profile" "$out" >"$work/$name.log" 2>&1 || rc=$?
    echo "$rc" >"$work/$name.rc"
    if ! test -f "$out/analysis.json"; then reject "$name did not produce analysis"; return; fi
    # Offline judgment must agree byte-for-byte, independent of the exit code.
    cp "$out/analysis.json" "$work/live.tmp"
    replay=0; "$turtle" analyze "$out" >>"$work/$name.log" 2>&1 || replay=$?
    if [ "$rc" != "$replay" ] || ! cmp -s "$work/live.tmp" "$out/analysis.json"; then reject "$name replay mismatch"; fi
    j="$out/analysis.json"
    jq -c --arg n "$name" --arg r "$role" '{
      cell:$n, role:$r, samples:.measurement_count, strict:.eligible_measurements, task:.successful_measurements,
      proof:[.attempts[]|select(.purpose=="capability")|.capability_proof],
      ordinary:[.attempts[]|select(.purpose=="sample")|{status:.qualification,exchange:.application_exchange,reason:.error,metrics:.participants[$r].metrics,
      flight_names:(.participants[$r].wire.flights // {}|keys)}]}' "$j" >>"$work/matrix.jsonl"
    if ! jq -e --arg s "$scenario" --arg r "$role" '.measured_role==$r and .measurement_count==2 and ([.attempts[]|select(.purpose=="sample")|.connection_id]|unique|length)==2 and ([.attempts[]|select(.purpose=="capability")]|length)==(if $s=="S2" or $s=="S4" then 1 else 0 end)' "$j" >/dev/null; then reject "$name attempt separation"; fi
    if [ "$kind" = wrong-name ]; then
        jq -e '.eligible_measurements==0 and all(.attempts[];.application_exchange=="failed")' "$j" >/dev/null || reject "$name accepted wrong identity"
    elif [ "$kind" != observed ] && [ "$kind" != native-pair ]; then
        jq -e --arg r "$role" --arg s "$scenario" '.eligible_measurements==0 and all(.attempts[]|select(.purpose=="sample");.application_exchange==(if $s=="S0" then "not_applicable" else "verified" end) and .participants[$r].metrics.authentication!=true and .participants[$r].metrics.transport_counts!=true and .participants[$r].metrics.pmu!=true and .participants[$r].timing.wall_ns==null)' "$j" >/dev/null || reject "$name stock/unobserved evidence"
    elif [ "$role" = server ] && { [ "$scenario" = S2 ] || [ "$scenario" = S4 ]; }; then
        jq -e '.eligible_measurements==0 and all(.attempts[]|select(.purpose=="sample"); .application_exchange=="verified" and .participants.server.metrics.ordinary_server_first==false and .separate_capability_proof!=true)' "$j" >/dev/null || reject "$name late greeting or bogus proof"
    else
        jq -e --arg r "$role" --arg s "$scenario" '.eligible_measurements==2 and all(.attempts[]|select(.purpose=="sample");.eligible and .task_success and .participants[$r].metrics.transport_counts==true and .participants[$r].metrics.authentication==true and .participants[$r].metrics.timed_records==true and (.participants[$r].timing|.wall_ns==(.end.ns-.begin.ns) and .begin.tid==.end.tid and .pmu_delta.tid==.begin.tid and .pmu_delta.running_ns==.pmu_delta.enabled_ns and .pmu_delta.running_ns>0) and (if $s=="S2" or $s=="S4" then .separate_capability_proof==true and .participants.server.metrics.ordinary_server_first==true else true end))' "$j" >/dev/null || reject "$name strict native role/PMU/evidence"
    fi
    if [ "$kind" = observed ] || [ "$kind" = native-pair ]; then
        for attempt in "$out"/attempt-*; do
            [ "$(jq -r .purpose "$attempt/attempt.json")" = sample ] || continue
            # Map each named anchor back to an actual measured-side syscall
            # whose accepted/consumed byte interval contains the boundary.
            jq -e --arg role "$role" --arg kind "$kind" --arg s "$scenario" --slurpfile raw "$attempt/$role.ndjson" '
                .participants[$role] as $p | $p.wire.flights as $fs |
                (($fs|keys|length)>=(if $kind=="native-pair" then 4 else 3 end)) and
                all($fs|to_entries[]; .key as $name | .value as $f |
                    (($name=="CH" or $name=="client_protected_flight")==($role=="client")) as $send |
                    ([$raw[]|select(.seq==$f.anchor.seq)][0]) as $io |
                    ([$raw[]|select(.kind=="io" and .source=="socket" and .sent==$send and .peek==false and .result>0 and .seq >= $p.lifecycle.ready.seq and .seq<$io.seq)|.result] | add // 0) as $offset |
                    (if $send then $f.begin else $f.end-1 end) as $byte |
                    $f.inner_message_times==null and $io.source=="socket" and $io.sent==$send and $io.result>0 and
                    $offset<=$byte and $byte<($offset+$io.result) and
                    $f.anchor.edge==(if $send then "begin" else "end" end) and
                    $f.anchor.ns==(if $send then $io.begin_ns else $io.ns end)) and
                ($p.timing.begin.seq==$p.lifecycle.hs_begin.seq) and
                ($p.timing.end.seq==(if $s=="S0" then $p.lifecycle.hs_complete
                   elif $s=="S1" then (if $role=="client" then $p.timeline.CAD.final_write_accept else $p.timeline.CAD.validated end)
                   elif $s=="S2" then (if $role=="client" then $p.timeline.SAD1.first_read_return else $p.timeline.SAD1.final_write_accept end)
                   elif $role=="client" then $p.timeline.SAD2.first_read_return else $p.timeline.SAD2.final_write_accept end).seq)' "$attempt/analysis.json" >/dev/null || reject "$name raw anchors/timing"
        done
    fi
    printf '%s\n' "$name"
}
for auth in server mtls; do
    for s in S0 S1 S2 S3 S4; do
        cell observed client "$auth" "$s" "$work/chat"
        cell observed server "$auth" "$s" "$work/chat"
        cell stock client "$auth" "$s" "$cli"
    done
done
cell native-pair client mtls S3 "$work/chat"
cell native-pair server server S3 "$work/chat"
cell unobserved client mtls S3 "$work/chat-no-sdk"
cell wrong-name client server S3 "$cli"
printf '%s\n' 'stock server: not admitted; gnutls-serv is an echo/HTTP protocol server, not a stdin/stdout plaintext bridge; no relabeled peer.' >"$work/stock-server-limit.txt"
sha256sum -c "$work/frozen.sha256" >"$work/check-frozen.log"
sha256sum -c "$work/apps.sha256" >"$work/check-apps.log"
rm "$work/live.tmp"
exit "$failed"
