#!/bin/sh
# Exercise failure/recovery in one collection, using two fresh connections.
set -eu
umask 077
if [ "$#" -ne 3 ]; then
    printf 'usage: %s FRAMEWORK_DIR BUILD_ONLY_JOB NEW_OUTPUT\n' "$0" >&2
    exit 2
fi
framework=$(realpath -e "$1")
build=$(realpath -e "$2/build")
unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH LD_DEBUG LD_DEBUG_OUTPUT TURTLE_PMU TURTLE_EVIDENCE_FD
mkdir -- "$3"
out=$(realpath -e "$3")
mkdir "$out/events" "$out/state"
export XDG_STATE_HOME="$out/state"
sha256sum -c "$build/expected-libs.sha256" >"$out/private-libraries.log"

keys=$(mktemp -d)
trap 'rm -rf -- "$keys"' EXIT
sh "$framework/turtle-issue-test-leaves.sh" "$keys/good" >"$out/issuance.log" 2>&1
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 1 \
    -config /dev/null -subj '/CN=Unrelated TURTLE test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -keyout "$keys/wrong.key" -out "$out/wrong-ca.crt" >>"$out/issuance.log" 2>&1

# Override only the client trust anchor and only on the first attempt. The
# wrapper immediately execs the submitted client, keeping the controller PID
# binding intact. No bridge flags or changes to the measured job are needed.
cat >"$out/fail-once.sh" <<'LAUNCH'
#!/bin/sh
set -eu
client=$1
wrong_ca=$2
lock=$3
shift 3
if mkdir "$lock" 2>/dev/null; then
    export TURTLE_CA="$wrong_ca"
    printf '%s\n' "$TURTLE_CONNECTION_ID" >"$lock/connection"
fi
exec "$client" "$@"
LAUNCH
chmod 700 "$out/fail-once.sh"
jq -n --arg out "$out" --arg bin "$build/bin" --arg keys "$keys/good" '
    {
      v:1,
      target:{role:"client", argv:[$out+"/fail-once.sh",$bin+"/client",
          $out+"/wrong-ca.crt",$out+"/once","{host}","{port}",$out+"/events","measured"]},
      peer:{argv:[$bin+"/server","{host}","{port}",$out+"/events","peer"]},
      scenario:"S0",auth:"server",warmups:0,repetitions:2,
      credentials:{ca:$keys+"/ca.crt",server:{cert:$keys+"/server.crt",key:$keys+"/server.key"}},
      required_metrics:["peer_task"],optional_metrics:["timing","pmu"]
    }' >"$out/profile.json"
rc=0
"$framework/turtle" run "$out/profile.json" "$out/result" >"$out/controller.log" 2>&1 || rc=$?
printf '%s\n' "$rc" >"$out/controller.exit"
[ "$rc" -eq 1 ]
failed_id=$(cat "$out/once/connection")
failed="$out/result/attempt-1"
later="$out/result/attempt-2"
jq -e --arg id "$failed_id" '
    .collection_complete and (.complete|not) and .measurement_count == 2 and
    .successful_measurements == 1 and [.attempts[].purpose] == ["sample","sample"] and
    [.attempts[].task_success] == [false,true] and .attempts[0].connection_id == $id and
    .attempts[1].connection_id != $id' "$out/result/analysis.json" >/dev/null
jq -se '
    .[0].exit.client == 1 and .[1].exit == {client:0,server:0} and
    .[0].run_id == .[1].run_id and
    (map(.pid | [.client,.server])|flatten|unique|length) == 4' \
    "$failed/attempt.json" "$later/attempt.json" >/dev/null
jq -se 'any(.[];.name=="hs_begin") and all(.[];.name!="hs_complete")' \
    "$failed/client.ndjson" >/dev/null

# Role process IDs and listener teardown are checked after the collection.
# TIME_WAIT entries are TCP bookkeeping, not leaked listening sockets.
for attempt in "$failed" "$later"; do
    for pid in $(jq -r '.pid[]' "$attempt/attempt.json"); do
        if kill -0 "$pid" 2>/dev/null; then
            printf 'role still alive: %s\n' "$pid" >&2
            exit 1
        fi
        printf 'reaped role PID %s\n' "$pid"
    done
    port=$(printf '%04X' "$(jq -r '.port' "$attempt/attempt.json")")
    status=0
    grep -Eiq ":[[:space:]]+[[:xdigit:]]{8}:$port[[:space:]]+[[:xdigit:]]{8}:[[:xdigit:]]{4}[[:space:]]+0A" \
        /proc/net/tcp || status=$?
    if [ "$status" -eq 0 ]; then
        printf 'listener still present: %s\n' "$port" >&2
        exit 1
    fi
    [ "$status" -eq 1 ]
    printf 'no listening socket on port 0x%s\n' "$port"
done >"$out/cleanup.log"
sha256sum -c "$build/expected-libs.sha256" >>"$out/private-libraries.log"
grep -F 'OpenSSL handshake failed' "$failed/client.stderr" >/dev/null
grep -Fi 'certificate verify failed' "$failed/client.stderr" >/dev/null
printf 'Verified certificate failure, both-role cleanup and later success: %s\n' "$out"
