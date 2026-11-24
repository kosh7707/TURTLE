#!/bin/sh
# A rehashed, syntactically valid run must still earn its pre-CF proof.
set -eu
cli=$1
src=$2
work=$3
gate="$src/attempt-1/attempt.json"
need=$(jq -er '.gate.pre_cf.required_queue_bytes|select(.>1)' "$gate")
for test in exact short one; do
    case "$test" in exact) queued=$need;; short) queued=$((need-1));; one) queued=1;; esac
    dir="$work/$test"
    cp -r "$src" "$dir"
    path="$dir/attempt-1/attempt.json"
    jq --argjson n "$queued" '.gate.client_recv_queue=$n|.gate.queue_socket.recv_queue=$n' "$path" >"$path.new"; mv "$path.new" "$path"
    sum=$(sha256sum "$path"); sum=${sum%% *}
    mf="$dir/manifest.json"
    jq --arg hash "$sum" '.attempts[0].sha256["attempt.json"]=$hash' "$mf" >"$mf.new"; mv "$mf.new" "$mf"
    "$cli" analyze "$dir" >"$dir/probe-replay.log" 2>&1 || :
    # Do not mistake stale derived output for successful replay.
    grep -q 'native-stream:' "$dir/probe-replay.log"
    if [ "$test" = exact ]; then
        jq -e '.capability_proof==true' "$dir/attempt-1/analysis.json" >/dev/null
    else
        jq -e '.capability_proof!=true' "$dir/attempt-1/analysis.json" >/dev/null
        jq -e '.eligible_measurements==0 and all(.attempts[]|select(.purpose=="sample");.separate_capability_proof!=true)' "$dir/analysis.json" >/dev/null
    fi
done
