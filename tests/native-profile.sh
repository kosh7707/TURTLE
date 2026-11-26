#!/bin/sh
# Lock the native CLI's launch-profile contract independently of PMU access.
set -eu
turtle=$1
openssl=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
export XDG_STATE_HOME="$work/state"
mkdir -m 700 "$XDG_STATE_HOME"
mkdir profiles
ln -s "$openssl" profiles/tls-client
sh "$(dirname "$turtle")/turtle-issue-test-leaves.sh" profiles/keys "$openssl" >issuance.log 2>&1

# Relative paths are interpreted against the profile's directory, not the
# working directory. User-facing metric names survive normalization.
cat >profiles/base.json <<'EOF'
{
  "v": 1,
  "target": {"role": "client", "argv": ["./tls-client","s_client","-quiet",
    "-tls1_3","-groups","P-256","-ciphersuites","TLS_AES_128_GCM_SHA256",
    "-verify_return_error","-verify_hostname","{peer_name}",
    "-CAfile","{ca}","-cert","{cert}","-key","{key}","-connect","{host}:{port}"]},
  "credentials": {"ca": "keys/ca.crt",
    "client": {"cert":"keys/client.crt","key":"keys/client.key"},
    "server": {"cert":"keys/server.crt","key":"keys/server.key"}},
  "expected": {"group":"secp256r1","cipher":"TLS_AES_128_GCM_SHA256","suite":4865},
  "optional_metrics": ["scenario_wall_ns","perf_counters"]
}
EOF
"$turtle" check profiles/base.json |
    jq -e '. == {schema:"turtle.native-check.v1",launch_configuration:"valid",
        measured_role:"client",peer:"stock",capability:null}' >/dev/null
"$turtle" run profiles/base.json run
jq -e --arg base "$(pwd -P)/profiles" --arg exe "$(realpath "$openssl")" '
    [.attempts[].purpose] == ["warmup","sample","sample"] and
    (.profile |
        .scenario=="S3" and .auth=="mtls" and .network=="loopback" and
        .timeout_seconds==10 and .warmups==1 and .repetitions==2 and
        .application=={request:"ping",greeting:"helo",response:"pong"} and
        .target.argv[0]==$exe and .stock_peer and
        .peer.argv[1:]==["--native-stream","server","mtls","{host}","{port}"] and
        .scenario_contract=="endpoint.v1" and
        .credentials.ca==($base+"/keys/ca.crt") and
        .credentials.client.key==($base+"/keys/client.key") and
        .credentials.server.cert==($base+"/keys/server.crt") and
        .expected=={group:23,suite:4865} and
        .required_metrics==[] and
        .optional_metrics==["scenario_wall_ns","perf_counters"] and
        .measurement=={})' run/manifest.json >/dev/null
jq -e '(.attempts | length)==3 and
    all(.attempts[]; .requested_metrics.scenario_wall_ns.metric=="timing" and
    .requested_metrics.perf_counters.metric=="pmu")' run/analysis.json >/dev/null

jq '.peer={argv:["./tls-client"]}' profiles/base.json >profiles/explicit.json
"$turtle" check profiles/explicit.json | jq -e '.peer=="specified"' >/dev/null

reject_profile() {
    filter=$1
    expected=$2
    jq "$filter" profiles/base.json >profiles/rejected.json
    for mode in check run; do
        set -- "$mode" profiles/rejected.json
        if [ "$mode" = run ]; then set -- "$@" uncreated; fi
        rc=0; "$turtle" "$@" >stdout.log 2>stderr.log || rc=$?
        test "$rc" -eq 1
        test ! -s stdout.log
        grep -Fx "turtle: $expected" stderr.log >/dev/null
        test ! -e uncreated
    done
}
reject_profile '.target.role="both" | .scenario="absent"' invalid_target_role
reject_profile '.scenario="absent"' invalid_scenario
reject_profile '.netem={}' netem_requires_isolated_network
reject_profile '.repetitions=0' attempt_count_out_of_range
reject_profile '.expected.suite=4866' contradictory_expected_negotiation
reject_profile '.expected.group="unrecognized"' unknown_negotiation_name:unrecognized
reject_profile '.required_metrics=["timing"]' duplicate_metric:scenario_wall_ns
reject_profile '.required_metrics=["imaginary"]' unknown_metric:imaginary
reject_profile '.measurement.capture="yes"' invalid_capture_flag
