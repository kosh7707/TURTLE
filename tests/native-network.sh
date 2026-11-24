#!/bin/sh
# Real trial, strict replay and two negative controls. No fallback or skip.
# Usage: native-network.sh TURTLE /path/to/independently-built/chat OUTPUT_PARENT
set -eu
turtle=$(realpath "${1:?TURTLE CLI}")
app=$(realpath "${2:?native matrix observed line client}")
parent=$(realpath -m "${3:?output parent}")
mkdir -p "$parent"
dir=$(mktemp -d "$parent/native-net-XXXXXX")
ns=$(cd "$(dirname "$0")/../tools" && pwd)/netns-exec.sh
jq -n --arg app "$app" '{v:1,target:{role:"client",argv:[$app,"client","{host}","{port}","{ca}","{cert}","{key}","{peer_name}"]},scenario:"S4",auth:"mtls",network:"netem",netem:{mtu:1000,additional_rtt_ms:16,client_to_server:{loss_pct:20,seed:77},server_to_client:{loss_pct:0,seed:19}},measurement:{capture:true},required_metrics:["capture"],timeout_seconds:30,warmups:0,repetitions:1,application:{request:"PING/1\n",greeting:"HELLO/1\n",response:"PONG/1\n"}}' >"$dir/netem.json"
"$ns" "$turtle" run "$dir/netem.json" "$dir/actual"
sample="$dir/actual/attempt-2"
jq -e '.purpose=="sample" and .task_success and .network.verified and .network.capture_verified and .network.requested.client_to_server.delay_ms==8 and .network.requested.server_to_client.delay_ms==8 and .network.requested.client_to_server.loss_pct==20 and (.participants.client.wire.flights | length)==4' "$sample/analysis.json" >/dev/null
# Directional ACK evidence is intentionally not required on every trial.
jq -e '(.network.tcp_ack==null) or (.network.tcp_ack==true and (.network.ack_witnesses|length)>0)' "$sample/analysis.json" >/dev/null
cp "$sample/analysis.json" "$dir/live.json"
"$turtle" analyze "$dir/actual"
cmp "$dir/live.json" "$sample/analysis.json"
cp -r "$dir/actual" "$dir/modified"
printf garbage >>"$dir/modified/attempt-2/network/server.pcap"
if "$turtle" analyze "$dir/modified" >"$dir/tamper.log" 2>&1; then exit 1; fi
grep -q invalid_attempt_inventory "$dir/tamper.log"
# Even a rehashed witness cannot qualify if qdisc settings do not match.
cp -r "$dir/actual" "$dir/contradictory"
path="$dir/contradictory/attempt-2/network/network.json"
jq '(.after.middle.qdisc[]|select(.dev=="ms" and .kind=="netem")|.options["loss-random"].loss)=0' "$path" >"$path.tmp"; mv "$path.tmp" "$path"
hash=$(sha256sum "$path"); hash=${hash%% *}
mf="$dir/contradictory/manifest.json"
jq --arg hash "$hash" '.attempts[1].sha256["network/network.json"]=$hash' "$mf" >"$mf.tmp"; mv "$mf.tmp" "$mf"
if "$turtle" analyze "$dir/contradictory"; then exit 1; fi
jq -e '.network.verified==false and .eligible==false' "$dir/contradictory/attempt-2/analysis.json" >/dev/null
sh "$(dirname "$0")/native-probe-replay.sh" "$turtle" "$dir/actual" "$dir"
# Strip network and mount capabilities inside a disposable namespace. A
# failure must be recorded without launching either TLS participant.
if "$ns" setpriv --bounding-set=-net_admin,-sys_admin "$turtle" run "$dir/netem.json" "$dir/denied"; then exit 1; fi
jq -e '.eligible==false and .network.verified==false and (.error|startswith("network_command_failed:"))' "$dir/denied/attempt-1/analysis.json" >/dev/null
echo "Native impaired S4 collection, identical replay and negative controls passed: $dir"
