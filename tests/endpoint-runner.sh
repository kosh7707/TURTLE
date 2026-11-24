#!/bin/sh
set -eu
app=$1
replay=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export TURTLE_REQUEST=ping TURTLE_GREETING=helo TURTLE_RESPONSE=pong
export TURTLE_RUN_ID=run TURTLE_CONNECTION_ID=conn TURTLE_EVIDENCE_FD=3
unset TURTLE_START_FD
trial() {
    export TURTLE_ROLE=$1 TURTLE_SCENARIO=$2
    shift 2
    stdin=$1 input=$2 mode=$3 rc=$4 calls=$5 published=$6
    got=0
    printf '%s' "$stdin" | "$app" "$input" "$mode" 3>"$work/events" >"$work/out" 2>"$work/err" || got=$?
    test "$got" = "$rc" && test "$(cat "$work/err")" = "$calls" &&
        test "$(cat "$work/out")" = "$published" || {
        echo "$TURTLE_ROLE $TURTLE_SCENARIO $mode: actual $got / $(cat "$work/err") / $(cat "$work/out")" >&2
        exit 1
    }
}
check() { jq -se "$1" "$work/events" >/dev/null; }

trial client S0 '' '' nouread 0 H ''
trial server S0 '' '' nouwrite 0 H ''
trial client S1 ping '' partial 0 HWW ''
check '[.[]|select(.name=="write_accepted")|.hex] == ["7069","6e67"]'
"$replay" "$work/events" "$TURTLE_REQUEST"
trial server S1 '' ping partial 0 HRR ping
trial client S2 '' helo partial 0 RRH helo
check '[.[]|select(.name=="hs_begin")|.first_operation] == ["read_plain"] and [.[]|select(.name=="hs_complete")|.confirmed_by] == ["handshake_until_local_complete"]'
check '[.[]|select(.name=="read_return" or .name=="hs_complete" or .name=="validated")|.name] == ["read_return","read_return","validated","hs_complete"]'
check 'all(.[]; .name!="auth_accepted" and .name!="peer_verified" and .kind!="identity")'
trial server S2 helo '' partial 0 EwwH ''
check '[.[]|select(.name=="server_first")|.value] == [true]'
trial client S3 ping pong all 0 HWR pong
trial server S3 pong ping all 0 HRW ping
trial client S4 ping helopong all 0 HWR helopong
check '[.[]|select(.name=="read_return")|.length] == [8] and [.[]|select(.name=="validated")|.length] == [4,4]'
trial client S4 ping helopong partial 0 HWWRRRR helopong
trial server S4 helopong ping all 0 EwHRW ping

# With the controller's response copy withheld, a prepared SDK server must
# still validate the whole request and finish its real TLS response. The
# missing copy fails post-task transcript verification, not the TLS operation.
for s in S3 S4; do
    if [ "$s" = S4 ]; then initial=helo; calls=EwwHRRWW; else initial=; calls=HRRWW; fi
    trial server "$s" "$initial" ping partial 3 "$calls" ping
    check '[.[]|select(.name=="ready" and .response_source=="prepared_environment")]|length==1'
    check 'map(select(.name=="validated"))[0].seq < map(select(.name=="write_accepted"))[-1].seq
           and map(select(.name=="end"))[0].seq > map(select(.name=="write_accepted"))[-1].seq'
done
trial server S3 pong pin partial 1 HRRR ''
check 'all(.[]; .name!="validated" and .name!="write_attempt")'

# stdout publication must not precede the response callback, even for the
# largest permitted request. Both file descriptors refer to the same file.
export TURTLE_ROLE=server TURTLE_SCENARIO=S3
TURTLE_REQUEST=$(head -c 16384 /dev/zero | tr '\000' x)
printf pong | "$app" "$TURTLE_REQUEST" all 3>"$work/events" >"$work/both" 2>&1
test "$(cat "$work/both")" = "HRW$TURTLE_REQUEST"
TURTLE_REQUEST=ping
rc=0
printf pong | "$app" ping all 3>"$work/events" >/dev/full 2>"$work/err" || rc=$?
test "$rc" = 3
test "$(cat "$work/err")" = HRW
check 'any(.[]; .name=="end")'

trial client S2 '' he partial 1 RR ''
check 'all(.[]; .name!="validated" and .name!="hs_complete" and .name!="end")'
trial server S2 helo '' noearly 2 E ''
check '[.[]|select(.name=="server_first")|.value] == [false]'
trial server S2 helo '' writeerror 3 Ew ''
check 'all(.[]; .name!="server_first" and .name!="write_accepted" and .name!="hs_complete")'
trial client S2 '' '' nouread 2 '' ''
check '[.[]|select(.name=="endpoint_unsupported")|.value] == [true]'
trial server S2 helo '' nouwrite 2 '' ''
check 'all(.[]; .name!="server_first")'
for bad in zero overflow; do
    trial client S2 '' helo "$bad" 3 R ''
    check 'all(.[]; .name!="read_return" and .name!="validated")'
    trial client S1 ping '' "$bad" 3 HW ''
    check 'all(.[]; .name!="write_accepted")'
done
trial server S3 pong pink all 3 HR ''
check 'all(.[]; .name!="validated" and .name!="write_attempt")'
trial client S1 piny '' all 3 '' ''

# 3,072 partial writes must not serialize 3,072 copies of the remaining
# 6 KiB request. Keep the original native offers; do not chunk for the DUT.
export TURTLE_ROLE=client TURTLE_SCENARIO=S1
TURTLE_REQUEST=pingpingping
for n in 1 2 3 4 5 6 7 8 9; do TURTLE_REQUEST=$TURTLE_REQUEST$TURTLE_REQUEST; done
printf '%s' "$TURTLE_REQUEST" | "$app" "$TURTLE_REQUEST" trickle 3>"$work/events" >"$work/out" 2>"$work/err"
test "$(wc -c <"$work/err")" -eq 3073
test "$(wc -c <"$work/events")" -lt 16777216
check '[.[]|select(.name=="write_attempt")] as $offers |
  ($offers|length)==3072 and ($offers[0].hex|length)==12288 and
  all(range(1;3072); . as $i | $offers[$i] |
      .offer_ref==$offers[0].seq and .suffix_offset==2*$i and .length==6144-2*$i and (has("hex")|not))'
"$replay" "$work/events" "$TURTLE_REQUEST"
