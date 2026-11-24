#!/bin/sh
# Exercise the published CLI using a TLS application with no observation SDK.
set -eu
turtle=$1
openssl=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
export XDG_STATE_HOME="$work/state"
mkdir -m 700 "$XDG_STATE_HOME"
reject() {
    if "$@" >rejection.log 2>&1; then
        printf 'Unexpected success: %s\n' "$*" >&2
        exit 1
    fi
}
jq -n --arg openssl "$openssl" '{
  v:1, scenario:"S3", auth:"mtls", warmups:0, repetitions:1,
  expected:{group:"secp256r1"}, optional_metrics:["perf_counters"],
  target:{role:"client",argv:[$openssl,"s_client","-quiet","-tls1_3",
    "-groups","P-256","-verify_return_error","-verify_hostname","{peer_name}",
    "-CAfile","{ca}","-cert","{cert}","-key","{key}","-connect","{host}:{port}"]}
}' >profile.json

# Host plaintext is positive evidence of exchange, not target authentication,
# TLS return timing, or hardware counters.
"$turtle" run profile.json basic
jq -e '.complete and .collection_complete and .eligible_measurements==0 and
    .measurement_count==1 and .measured_role=="client" and
    (.attempts[0] | .application_exchange=="verified" and
      .scenario_support=="unconfirmed" and .measured_transport_hook.verified==null and
      .measured_transport_hook.reason=="hook_unobserved" and
      .participants.server.wire.transport_hook.verified==true and
      .prepared_start.verified==null and
      .prepared_start.rendezvous=="unsynchronized_fallback" and .benchmark_timing_ns==null and
      .requested_metrics.perf_counters.available==null and
      .participants.server.negotiated.group==23)' basic/analysis.json >/dev/null
printf ping | cmp - basic/attempt-1/server.stdout
printf pong | cmp - basic/attempt-1/client.stdout
cp basic/analysis.json live.json
"$turtle" analyze basic
cmp live.json basic/analysis.json

# The peer is the observed reference server, not this unobserved client.
jq '.required_metrics=["peer_task"]' profile.json >peer.json
"$turtle" run peer.json peer
jq -e '.attempts[0] | .requested_metrics.peer_task.available==true and
    .participants.server.metrics.peer_task==true and .participants.client.metrics.peer_task==null' peer/analysis.json >/dev/null

# With only an initial X25519 share, this same P-256 server must request a
# second ClientHello. The resulting TLS exchange works, but is not one RTT.
jq '.target.argv |= map(if .=="P-256" then "X25519:P-256" else . end)' profile.json >hrr.json
reject "$turtle" run hrr.json hrr
jq -e '.eligible_measurements==0 and (.attempts[0] |
    .application_exchange=="verified" and .qualification=="contradicted" and
    .participants.server.facts.hrr==true)' hrr/analysis.json >/dev/null

# An explicit peer is not overwritten by the stock server.
jq '.peer={argv:["/bin/false"]}' profile.json >explicit.json
"$turtle" check explicit.json | jq -e '.peer=="specified"' >/dev/null
reject "$turtle" run explicit.json explicit
jq -e '.error=="server_exited_before_listen" and .eligible==false' explicit/attempt-1/analysis.json >/dev/null

# Failing authentication during warmup prevents all ordinary measurements.
jq '.warmups=1 | .target.argv |= map(if .=="{peer_name}" then "wrong.invalid" else . end)' profile.json >wrong-name.json
reject "$turtle" run wrong-name.json bad-auth
jq -e '.measurement_count==0 and .eligible_measurements==0 and
    [.attempts[].purpose]==["warmup"] and .attempts[0].application_exchange=="failed"' bad-auth/analysis.json >/dev/null

# Same missing metric becomes an explicit failure when required; a real local
# retry has fresh IDs and cannot rewrite the original failed attempt.
jq 'del(.optional_metrics) | .required_metrics=["perf_counters"]' profile.json >strict.json
reject "$turtle" run strict.json strict
jq -e '(.complete|not) and .eligible_measurements==0 and
    (.attempts[0] | .application_exchange=="verified" and
     .required_metrics_available==false)' strict/analysis.json >/dev/null
id=$(jq -er '.attempts[0].connection_id' strict/analysis.json)
sha256sum strict/manifest.json strict/analysis.json strict/attempt-1/attempt.json >original.sha256
reject "$turtle" retry strict "$id" retried
jq -e --arg id "$id" '.retry_of.connection_id==$id' retried/manifest.json >/dev/null
jq -e --arg id "$id" '.attempts[0].connection_id!=$id and .eligible_measurements==0' retried/analysis.json >/dev/null
sha256sum -c original.sha256 >/dev/null

# The separate diagnostic is finalized after ordinary samples. A failed
# required diagnostic is retryable; the same missing optional one is not.
for kind in required optional; do
    name="cpu-$kind"
    jq --arg kind "$kind" --arg tool "$work/no-such-perf" '
        del(.optional_metrics) | .[($kind+"_metrics")]=["cpu_samples"] |
        .measurement.cpu_samples={perf:$tool}' profile.json >"$name.json"
    expected=0; if [ "$kind" = required ]; then expected=1; fi
    rc=0; "$turtle" run "$name.json" "$name" || rc=$?
    [ "$rc" -eq "$expected" ]
    jq -e --arg k "$kind" '.attempts[0] |
        .requested_metrics.cpu_samples.available==null and
        .operation_ok==($k=="optional")' "$name/analysis.json" >/dev/null
    cp "$name/analysis.json" live.json
    replay=0; "$turtle" analyze "$name" || replay=$?
    [ "$rc" -eq "$replay" ]; cmp live.json "$name/analysis.json"
    cpu_id=$(jq -er '.attempts[0].connection_id' live.json)
    # Derived files are not authority for retry; neither trust nor modify them.
    printf '{}\n' >"$name/analysis.json"
    printf '{}\n' >"$name/attempt-1/analysis.json"
    find "$name" -type f -exec sha256sum {} + >original.sha256
    reject "$turtle" retry "$name" "$cpu_id" "$name-retry"
    if [ "$kind" = required ]; then
        jq -e --arg id "$cpu_id" '.retry_of.connection_id==$id' "$name-retry/manifest.json" >/dev/null
        jq -e --arg id "$cpu_id" '.attempts[0].connection_id!=$id and
            .attempts[0].operation_ok==false' "$name-retry/analysis.json" >/dev/null
    else
        grep -q 'retry_requires_failed_measurement' rejection.log
        test ! -e "$name-retry"
    fi
    sha256sum -c original.sha256 >/dev/null
done

# An edited manifest is no longer authorized to execute, even in its original
# directory. Offline replay independently rejects changes to source evidence.
jq '.profile.target.argv=["/bin/true"]' strict/manifest.json >edit.json
mv edit.json strict/manifest.json
reject "$turtle" retry strict "$id" not-created
grep -q 'untrusted_retry_source' rejection.log
test ! -e not-created
printf changed >>basic/attempt-1/client.stdout
reject "$turtle" analyze basic
grep -q 'invalid_attempt_inventory' rejection.log

# A new S2 trial is an ordinary connection, never a stopped-client capability
# run. This unobserved client has no plaintext-return timestamp; the stock
# server's local early write is not evidence of pre-CF client delivery.
jq '.scenario="S2" | .target.argv += ["-ciphersuites","TLS_AES_128_GCM_SHA256"]' profile.json > early.json
"$turtle" run early.json early
jq -e '(.attempts|length)==1 and (.attempts[0] |
    .purpose=="sample" and .capability_proof==null and .separate_capability_proof==null and
    .participants.server.metrics.ordinary_server_first==true and
    .participants.client.timing.wall_ns==null)' early/analysis.json >/dev/null
cp early/analysis.json live.json
"$turtle" analyze early
cmp live.json early/analysis.json

# Selecting the expected numeric ID restricts only our stock participants.
jq '.expected.suite=4865' early.json > same-suite.json
"$turtle" run same-suite.json same-suite
jq -e 'all(.attempts[];.participants.server.negotiated.suite==4865)' same-suite/analysis.json >/dev/null

# The persisted contract must agree with the source attempt, not just the
# mutable profile; unknown semantics and unsolicited capability schedules fail.
for change in mismatch unknown probe; do
    cp -R early "bad-$change"
    mf="bad-$change/manifest.json"
    case $change in
        mismatch) expr='del(.profile.scenario_contract)'; reason=scenario_contract_mismatch ;;
        unknown) expr='.profile.scenario_contract="future"'; reason=unsupported_scenario_contract ;;
        probe) expr='.profile.probe_client=.profile.peer.argv'; reason=unexpected_probe_configuration ;;
    esac
    jq "$expr" "$mf" >edit.json && mv edit.json "$mf"
    reject "$turtle" analyze "bad-$change"
    grep -q "$reason" rejection.log
done

# Even a re-hashed source cannot launder an unbound reporter-selected PID.
dir=$(jq -er '.attempts[]|select(.purpose=="sample")|.directory' same-suite/manifest.json)
raw="same-suite/$dir/attempt.json"
jq 'del(.pid.server)' "$raw" > edit.json
mv edit.json "$raw"
hash=$(sha256sum "$raw" | cut -d' ' -f1)
jq --arg hash "$hash" --arg dir "$dir" '(.attempts[]|select(.directory==$dir)|.sha256["attempt.json"])=$hash' same-suite/manifest.json > edit.json
mv edit.json same-suite/manifest.json
reject "$turtle" analyze same-suite
grep -q 'unbound_completed_participant:server' rejection.log
