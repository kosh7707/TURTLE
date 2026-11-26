#!/bin/sh
# Both real TLS participants are READY when the inventory hasher starts.
set -eu
turtle=$1
profile=$2
work=$3
mkdir -p "$work/bin"
REAL_SHA256SUM=$(command -v sha256sum)
export REAL_SHA256SUM
cat >"$work/bin/sha256sum" <<'HASH'
#!/bin/sh
case "$1" in
    /proc/self/fd/*)
        if [ -n "${CANCEL_CONTROLLER:-}" ]; then
            kill -TERM "$CANCEL_CONTROLLER"
        fi
        exec sleep 5 ;;
esac
exec "$REAL_SHA256SUM" "$@"
HASH
chmod +x "$work/bin/sha256sum"
export PATH="$work/bin:$PATH"

# The wrapper execs turtle, so the shim targets the exact controller PID
# without racing a timer against setup or depending on the helper topology.
if sh -c 'export CANCEL_CONTROLLER=$$; exec "$@"' sh "$turtle" run "$profile" "$work/cancelled"; then
    echo "cancelled preparation unexpectedly succeeded" >&2
    exit 1
fi
jq -e '.status=="interrupted"' "$work/cancelled/manifest.json" >/dev/null
attempt="$work/cancelled/attempt-1"
jq -e '.error=="interrupted" and any(.images[];.reason=="image_snapshot_cancelled") and
    all(.prepared_start.roles.client,.prepared_start.roles.server;
        .ready_received_ns>0 and (has("release_begin_ns")|not))' "$attempt/attempt.json" >/dev/null
for role in client server; do
    jq -se 'any(.[];.name=="ready") and
        all(.[];.v==2 and .name!="hs_begin" and .kind!="observer_complete")' \
        "$attempt/$role.ndjson" >/dev/null
done

# Slow optional evidence alone must not cancel the ordinary TLS measurement.
CANCEL_CONTROLLER= "$turtle" run "$profile" "$work/timeout"
attempt="$work/timeout/attempt-1"
jq -e '.error==null and all(.images[];.available==false) and
    .prepared_start.outcome=="joint_release" and
    all(.prepared_start.roles.client,.prepared_start.roles.server;.release=="G")' "$attempt/attempt.json" >/dev/null
for role in client server; do
    jq -se 'any(.[];.name=="hs_begin") and .[-1].kind=="observer_complete"' \
        "$attempt/$role.ndjson" >/dev/null
    jq -e --arg role "$role" '.participants[$role].observer_stream=="complete"' \
        "$attempt/analysis.json" >/dev/null
done
