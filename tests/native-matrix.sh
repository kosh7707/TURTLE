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
    if [ "$kind" = native-pair ] || [ "$kind" = unobserved-peer ]; then
        other=server; [ "$role" = client ] || other=client
        peer=$exe; required='["tls_flights","peer_task"]'
        if [ "$kind" = unobserved-peer ]; then peer="$work/chat-no-sdk"; required='["peer_task"]'; fi
        jq --arg other "$other" --arg exe "$peer" --argjson req "$required" '.peer.argv=[$exe,$other,"{host}","{port}","{ca}","{cert}","{key}","{peer_name}"]|.required_metrics=$req' "$profile" >"$profile.tmp"
        mv "$profile.tmp" "$profile"
    elif [ "$kind" = observed ] && { [ "$scenario" = S2 ] || [ "$scenario" = S4 ]; }; then
        jq '.required_metrics=["ordinary_server_first"]' "$profile" >"$profile.tmp"
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
    if ! jq -e --arg r "$role" '.measured_role==$r and .measurement_count==2 and ([.attempts[]|select(.purpose=="sample")|.connection_id]|unique|length)==2 and all(.attempts[]; .purpose=="sample" and .capability_proof==null and .separate_capability_proof==null)' "$j" >/dev/null; then reject "$name attempt separation"; fi
    if [ "$kind" = observed ] || [ "$kind" = native-pair ]; then
        jq -e 'all(.attempts[]|select(.purpose=="sample"); .prepared_start.verified==true and .prepared_start.basis=="prepared_rendezvous")' "$j" >/dev/null || reject "$name ordinary joint release"
    fi
    for attempt in "$out"/attempt-*/attempt.json; do
        if [ "$kind" = observed ] || [ "$kind" = native-pair ]; then
            jq -e '. as $a | .prepared_start.roles as $r |
                all("client", "server"; . as $role | $a.images[$role] |
                    .pid==$a.pid[$role] and .phase=="prepared" and
                    .host_begin_ns>=([$r[].ready_received_ns]|max) and
                    .host_end_ns>=.host_begin_ns and .host_end_ns<=([$r[].release_begin_ns]|min) and
                    (if .available then .mapped[.exe]!=null else
                        .available==false and (.reason|type)=="string" and (has("mapped")|not) end))' \
                "$attempt" >/dev/null || reject "$name image snapshot outside joint preparation"
        else
            jq -e 'all(.images.client, .images.server;
                .available==false and .reason=="joint_preparation_unavailable" and (has("mapped")|not))' \
                "$attempt" >/dev/null || reject "$name image snapshot without joint preparation"
        fi
    done
    if [ "$kind" = unobserved-peer ]; then
        [ "$rc" = 1 ] && jq -e --arg r "$role" '.eligible_measurements==0 and all(.attempts[];
            .application_exchange=="verified" and .participants[$r].metrics.peer_task==true and
            .requested_metrics.peer_task.available==null and .required_metrics_available==false)' "$j" >/dev/null || reject "$name granted measured participant evidence to unobserved peer"
    elif [ "$kind" = wrong-name ]; then
        jq -e '.eligible_measurements==0 and all(.attempts[];.application_exchange=="failed")' "$j" >/dev/null || reject "$name accepted wrong identity"
    elif [ "$kind" != observed ] && [ "$kind" != native-pair ]; then
        jq -e --arg r "$role" --arg s "$scenario" '.eligible_measurements==0 and all(.attempts[]|select(.purpose=="sample");.application_exchange==(if $s=="S0" then "not_applicable" else "verified" end) and .participants[$r].metrics.authentication!=true and .participants[$r].metrics.transport_counts!=true and .participants[$r].metrics.pmu!=true and .participants[$r].timing.wall_ns==null)' "$j" >/dev/null || reject "$name stock/unobserved evidence"
    elif [ "$role" = client ] && [ "$scenario" = S2 ]; then
        # This independent chat app explicitly handshakes before its read. Its
        # real plaintext return, TLS flights and thread counters are diagnostic,
        # not evidence of the read-first SDK scenario.
        jq -e '.eligible_measurements==0 and .successful_measurements==0 and all(.attempts[];
            .application_exchange=="verified" and .participants.server.metrics.ordinary_server_first==true and
            (.participants.client | .metrics.s2_read_first==null and .metrics.task!=true and
                .metrics.transport_counts==true and .metrics.authentication==true and .metrics.timed_records==true and
                .timing.end.seq==.timeline.SAD1.last_read_return.seq and .timing.end.seq>.lifecycle.hs_complete.seq and
                .timing.wall_ns>0 and .timing.pmu_delta.running_ns>0))' "$j" >/dev/null || reject "$name handshake-first diagnostic"
    elif [ "$role" = server ] && { [ "$scenario" = S2 ] || [ "$scenario" = S4 ]; }; then
        jq -e '.eligible_measurements==0 and all(.attempts[]|select(.purpose=="sample"); .application_exchange=="verified" and .participants.server.metrics.ordinary_server_first==false and .separate_capability_proof!=true)' "$j" >/dev/null || reject "$name late greeting or bogus proof"
    else
        jq -e --arg r "$role" --arg s "$scenario" '.eligible_measurements==2 and all(.attempts[]|select(.purpose=="sample");.eligible and .task_success and .prepared_start.verified==true and .prepared_start.basis=="prepared_rendezvous" and .participants[$r].metrics.transport_counts==true and .participants[$r].metrics.authentication==true and .participants[$r].metrics.timed_records==true and (.participants[$r].timing|.wall_ns==(.end.ns-.begin.ns) and .begin.tid==.end.tid and .pmu_delta.tid==.begin.tid and .pmu_delta.running_ns==.pmu_delta.enabled_ns and .pmu_delta.running_ns>0) and (if $s=="S2" or $s=="S4" then .separate_capability_proof==null and .participants.server.metrics.ordinary_server_first==true else true end))' "$j" >/dev/null || reject "$name strict native role/PMU/evidence"
    fi
    if [ "$kind" = observed ] && { [ "$scenario" = S2 ] || [ "$scenario" = S4 ]; }; then
        jq -e 'all(.attempts[]|select(.purpose=="sample");
            .requested_metrics.ordinary_server_first.available==.participants.server.metrics.ordinary_server_first)' "$j" >/dev/null || reject "$name ordinary server-first metric owner"
    fi
    if [ "$kind" = observed ] || [ "$kind" = native-pair ]; then
        for attempt in "$out"/attempt-*; do
            [ "$(jq -r .purpose "$attempt/attempt.json")" = sample ] || continue
            # Map each named anchor back to an actual measured-side syscall
            # whose accepted/consumed byte interval contains the boundary.
            jq -e --arg role "$role" --arg kind "$kind" --arg s "$scenario" --slurpfile raw "$attempt/$role.ndjson" '
                .participants[$role] as $p | $p.wire.flights as $fs |
                (($fs|keys|length)==4) and
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
    if [ "$kind" = observed ] && [ "$role" = server ] && { [ "$scenario" = S3 ] || [ "$scenario" = S4 ]; }; then
        for attempt in "$out"/attempt-*/attempt.json; do
            jq -e --slurpfile p "$profile" --arg s "$scenario" '
              (if $s=="S4" then ($p[0].application.greeting|utf8bytelength) else 0 end) as $skip |
              [.ranges[]|select(.role=="server" and .channel=="stdout")] as $cad |
              [.ranges[]|select(.role=="server" and .channel=="stdin" and .end>$skip)] as $reply |
              $cad[-1].end==($p[0].application.request|utf8bytelength) and ($reply|length)>0 and
              $cad[-1].host_end_ns <= $reply[0].host_begin_ns' "$attempt" >/dev/null ||
                reject "$name supplied an ordinary server response before complete CAD"
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
cell unobserved-peer client mtls S3 "$work/chat"
cell unobserved-peer server mtls S3 "$work/chat"
printf '%s\n' 'stock server: not admitted; gnutls-serv is an echo/HTTP protocol server, not a stdin/stdout plaintext bridge; no relabeled peer.' >"$work/stock-server-limit.txt"
sha256sum -c "$work/frozen.sha256" >"$work/check-frozen.log"
sha256sum -c "$work/apps.sha256" >"$work/check-apps.log"
rm "$work/live.tmp"
exit "$failed"
