#!/bin/sh
# Build a separate C project using only the installed SDK and its own TLS.
# The external application doesn't know the scenario, payloads or event names.
set -eu
build=$(cd "${1:?framework build}" && pwd)
mkdir -p "${2:?output parent}"
work=$(mktemp -d "$(cd "$2" && pwd)/run-XXXXXX")
export XDG_STATE_HOME="$work/state"
mkdir -m 700 "$XDG_STATE_HOME"
fixture=$(cd "$(dirname "$0")/endpoint-integration" && pwd)
cmake --install "$build" --prefix "$work/sdk" >"$work/install.log"
cmake -S "$fixture" -B "$work/app" -DCMAKE_PREFIX_PATH="$work/sdk" >"$work/config.log"
cmake --build "$work/app" >"$work/build.log"
turtle="$work/sdk/bin/turtle"
"$work/sdk/bin/turtle-issue-test-leaves.sh" "$work/keys" >"$work/pki.log" 2>&1
replay() {
    cp "$1/analysis.json" "$1.live.json"
    "$turtle" analyze "$1"
    cmp "$1.live.json" "$1/analysis.json"
}
for role in client server; do
    for auth in server mtls; do
        for scenario in S0 S1 S2 S3 S4; do
            run="$work/$role-$auth-$scenario"
            jq -n --arg role "$role" --arg auth "$auth" --arg s "$scenario" \
                --arg app "$work/app/consumer" --arg keys "$work/keys/" '{
                v:1, target:{role:$role,argv:[$app,$role,"{host}","{port}","{ca}","{cert}","{key}","{peer_name}","--wire"]},
                auth:$auth,scenario:$s,warmups:0,repetitions:1,
                credentials:{ca:($keys+"ca.crt"),server:{cert:($keys+"server.crt"),key:($keys+"server.key")},
                    client:{cert:($keys+"client.crt"),key:($keys+"client.key")}},
                application:{request:"request",greeting:"hello",response:"reply"},
                required_metrics:["timing","task"],optional_metrics:["authentication","library_io"]}' >"$run.json"
            "$turtle" run "$run.json" "$run"
            if [ "$scenario" = S3 ] || [ "$scenario" = S4 ]; then
                # This loopback fixture shares the controller's monotonic
                # clock. The SDK sent its reply before the supervisor even
                # received CAD; the real stdio copy still follows CAD.
                jq -e --slurpfile a "$run/attempt-1/analysis.json" '
                  $a[0].participants.server as $srv |
                  [.ranges[]|select(.role=="server" and .channel=="stdout")] as $cad |
                  [.ranges[]|select(.role=="server" and .channel=="stdin")] as $input |
                  $srv.lifecycle.ready.response_source=="prepared_environment" and
                  $srv.timeline.CAD.validated.seq < $srv.timeline.SAD2.first_write_attempt.seq and
                  $srv.timeline.SAD2.final_write_accept.ns <= $cad[0].host_end_ns and
                  $cad[-1].host_end_ns <= $input[-1].host_begin_ns' "$run/attempt-1/attempt.json" >/dev/null
            fi
            jq -e --arg role "$role" --arg s "$scenario" '
                [.attempts[].purpose]==["sample"] and .successful_measurements==1 and
                (.attempts[0] |
                 .operation_ok and .task_success and .benchmark_timing_ns>0 and
                 .requested_metrics.authentication.available==null and
                 .requested_metrics.library_io.available==true and
                 .measured_transport_hook=={verified:true,source:"library_io",reason:null} and
                 (.pmu_status!="available" or .eligible==true) and
                 .separate_capability_proof==null and
                 (if ($s=="S2" or $s=="S4") then .participants.server.metrics.ordinary_server_first==true else true end) and
                 (.participants.client as $c |
                  if $s=="S2" then
                    ($c.timing.end.seq==$c.timeline.SAD1.first_read_return.seq) and
                    ($c.timing.end.seq<$c.lifecycle.hs_complete.seq) and
                    (if $role=="client" then $c.timing.end.seq<$c.timeline.SAD1.last_read_return.seq else true end)
                  elif $s=="S4" then $c.timeline.CAD.final_write_accept.seq<$c.timeline.SAD1.first_read_return.seq
                  else true end))' "$run/analysis.json" >/dev/null
            replay "$run"
        done
    done
done
# Only the DUT hook is removed. The same peer still has full wire coverage;
# that coverage must not qualify the measured client on its behalf.
run="$work/no-dut-wire"
jq '.target.argv -= ["--wire"]' "$work/client-mtls-S2.json" >"$run.json"
"$turtle" run "$run.json" "$run"
jq -e '.successful_measurements==1 and .eligible_measurements==0 and
    (.attempts[0] | .operation_ok and .task_success and .eligible==false and
     .qualification=="transport_hook_unconfirmed" and
     .measured_transport_hook=={verified:null,source:null,reason:"hook_unobserved"} and
     .benchmark_timing_ns>0 and .participants.client.timing.end.seq==.participants.client.timeline.SAD1.first_read_return.seq and
     .requested_metrics.library_io.available==null and .participants.server.metrics.library_io==true)' "$run/analysis.json" >/dev/null
replay "$run"

# Conversely, a missing hook on the *unmeasured* peer must not disqualify a
# fully instrumented DUT. The peer still uses its configured TLS operations.
run="$work/no-peer-wire"
jq '.peer={argv:(.target.argv | .[1]="server" | . - ["--wire"])}' "$work/client-mtls-S2.json" >"$run.json"
"$turtle" run "$run.json" "$run"
jq -e '.successful_measurements==1 and
    (.attempts[0] | .task_success and .benchmark_timing_ns>0 and
     .measured_transport_hook=={verified:true,source:"library_io",reason:null} and
     .participants.server.metrics.library_io==null and (.pmu_status!="available" or .eligible==true))' "$run/analysis.json" >/dev/null
replay "$run"
# A missing separate profiler must not rewrite task success, turn warmups into
# samples, or leave the run totals counting samples the final rows exclude.
for kind in optional required; do
    run="$work/missing-$kind-profiler"
    jq --arg kind "$kind" --arg missing "$work/no-such-perf" '
        .warmups=1 | .repetitions=2 |
        .[($kind+"_metrics")] += ["cpu_samples"] |
        .measurement.cpu_samples={perf:$missing}' "$work/client-mtls-S0.json" >"$run.json"
    rc=0; "$turtle" run "$run.json" "$run" || rc=$?
    if [ "$kind" = required ]; then
        test "$rc" -eq 1
    else
        test "$rc" -eq 0
    fi
    jq -e --arg kind "$kind" '
        (.attempts | map(select(.purpose=="sample"))) as $samples |
        .collection_complete and .complete==($kind=="optional") and
        [.attempts[].purpose]==["warmup","sample","sample"] and
        (.attempts[0] | .warmup_allows_measurement and .qualification=="warmup_only" and (.qualified|not)) and
        .samples==2 and .measurement_count==2 and .successful_measurements==2 and
        .qualified_samples==([$samples[] | select(.qualified)] | length) and
        .eligible_measurements==.qualified_samples and
        (.cpu_samples.reason as $reason | $reason!=null and all($samples[];
            .task_success and .qualified==.eligible and
            .requested_metrics.cpu_samples.available==null and
            .requested_metrics.cpu_samples.reason==$reason and
            (if $kind=="required" then
                .qualified==false and .operation_ok==false and .required_metrics_available==false and
                (.ordinary_qualified_without_diagnostic==(.qualification=="required_diagnostic_missing")) and
                (if .pmu_status=="available" then .ordinary_qualified_without_diagnostic else true end)
             else .operation_ok and .required_metrics_available and
                (has("ordinary_qualified_without_diagnostic")|not)
             end)))' "$run/analysis.json" >/dev/null
    cp "$run/analysis.json" "$run.live.json"
    replay_rc=0; "$turtle" analyze "$run" || replay_rc=$?
    test "$rc" -eq "$replay_rc"
    cmp "$run.live.json" "$run/analysis.json"
done
sh "$fixture/../native-preparation-cancel.sh" "$turtle" "$work/client-mtls-S0.json" "$work/prepare"
printf '20 wired role/auth/scenario cells, 2 asymmetric hook controls and identical replays: %s\n' "$work"
