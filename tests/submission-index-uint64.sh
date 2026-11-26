#!/bin/sh
# Exercise the same reader the matrix index uses, without generating 80 fake jobs.
set -eu
index=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed '/^# Matrix entry point/,$d' "$index" > "$tmp/reader"
. "$tmp/reader"
trace=$tmp/hook.csv
receipt=$tmp/case.json
head='event,monotonic_ns,bytes'
maximum=18446744073709551615

write_trace() {
    printf '%s\nbefore_send_offer,%s,4\nafter_recv,%s,%s\n' "$head" "$1" "$2" "$3" > "$trace"
}
write_case() {
    cat > "$receipt" <<EOF
{"benchmark":{"evidence":[{
  "connection_id":"probe","verified":true,"transport_csv":"$trace","transport_count":"$trace.count",
  "transport":{"before_send_offers":1,"after_recv_returns":${5:-1},
    "send_size_semantics":"requested_write_bytes","receive_size_semantics":"positive_return_bytes",
    "coverage_span":{"clock":"CLOCK_MONOTONIC","delta_ns":$3,
      "start":{"role":"client","row":1,"layer":"ciphertext_hook","direction":"send",
               "event":"before_send_offer","monotonic_ns":$1,"bytes":4},
      "end":{"role":"client","row":${6:-2},"layer":"ciphertext_hook","direction":"receive",
             "event":"after_recv","monotonic_ns":$2,"bytes":$4}}}
}]}}
EOF
}
check() { check_transport_rows "$trace" "$1" "$receipt" benchmark probe client; }
admit() { [ "$(check "$1")" = "$2" ] || fail "rejected expected trace ($3)"; }
reject() { if check "$1" >/dev/null; then fail "accepted invalid trace ($2)"; fi; }

# Legacy raw-only mode needs no JSON precision support but still orders exactly.
printf '{}\n' > "$receipt"
write_trace 9007199254740992 9007199254740993 "$maximum"
admit true 2 'legacy increasing uint64'
write_trace 9007199254740993 9007199254740992 "$maximum"
reject true 'legacy adjacent inversion'
if ! (require_exact_json); then
    echo 'Skipped JSON cross-check cases: this jq backend cannot retain uint64 literals.'
    exit 77
fi

write_trace 9007199254740992 9007199254741993 "$maximum"
write_case 9007199254740992 9007199254741993 1001 "$maximum"
admit false 2 'exact interval above binary64 limit'
write_case 9007199254740992 9007199254741993 1000 "$maximum"
reject false 'rounded but incorrect interval'
write_case 9007199254740992 9007199254741992 1001 "$maximum"
reject false 'adjacent endpoint incorrectly equated'
write_case 9007199254740992 9007199254741993 1001 18446744073709551614
reject false 'adjacent bytes incorrectly equated'

write_trace 9999999999 10000000000 "$maximum"
write_case 9999999999 10000000000 1 "$maximum"
admit false 2 'delta borrowing across limbs'
write_trace 1 "$maximum" "$maximum"
write_case 1 "$maximum" 18446744073709551614 "$maximum"
admit false 2 'span and bytes up to the uint64 limit'
write_trace 1 18446744073709551616 "$maximum"
reject true 'timestamp above uint64 range'
write_trace 1 "$maximum" 18446744073709551616
reject true 'byte count above uint64 range'
write_trace "$maximum" "$maximum" "$maximum"
write_case "$maximum" "$maximum" 0 "$maximum"
admit false 2 'equal clock reading, zero elapsed ns'

printf '%s\nbefore_send_offer,9007199254740993,4\nafter_recv,9007199254740992,1\nafter_recv,9007199254742000,%s\n' \
    "$head" "$maximum" > "$trace"
write_case 9007199254740993 9007199254742000 1007 "$maximum" 2 3
reject false 'adjacent timestamps inverted inside otherwise correct endpoints'

write_trace 1 "$maximum" "$maximum"
write_case 1 "$maximum" 18446744073709551614 "$maximum"
sed 's/"direction":"receive"/"direction":"send"/' "$receipt" > "$tmp/bad"
mv -- "$tmp/bad" "$receipt"
reject false 'wrong endpoint direction'
write_case 1 "$maximum" 18446744073709551614 "$maximum"
sed 's/"clock":"CLOCK_MONOTONIC"/"clock":"CLOCK_REALTIME"/' "$receipt" > "$tmp/bad"
mv -- "$tmp/bad" "$receipt"
reject false 'wrong clock domain'
echo 'Exact uint64 ordering, interval and endpoint checked (including archived raw-only mode).'
