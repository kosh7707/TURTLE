#!/bin/sh
set -eu
server=$1 client=$2 openssl=$3
tmp=$(mktemp -d "${TMPDIR:-/tmp}/chat-test.XXXXXX")
spid= cpid=
cleanup() {
    for pid in $spid $cpid; do kill -KILL "$pid" 2>/dev/null || :; done
    for pid in $spid $cpid; do wait "$pid" 2>/dev/null || :; done
    rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
cd "$tmp"
unset CHAT_CERT_DIR
mkfifo server.in client.in

fail() {
    echo "$*" >&2
    cat server.log client.log >&2
    exit 1
}
# Wait for observable events, not for an assumed TLS/network delay.
eventually() {
    n=0
    until "$@"; do
        n=$((n + 1))
        [ "$n" -lt 10 ] || fail "Timed out: $*"
        sleep 1
    done
}

start_server() {
    : > client.log
    "$server" 0 <server.in >server.log 2>&1 &
    spid=$!
    exec 3>server.in
    eventually grep -Eq '^Listening on 127\.0\.0\.1:[0-9]+$' server.log
    port=$(sed -n 's/^Listening on 127\.0\.0\.1://p' server.log)
}
start_client() {
    "$client" "$port" 3>&- <client.in >client.log 2>&1 &
    cpid=$!
    exec 4>client.in
}
exited() { ! kill -0 "$1" 2>/dev/null; }
finish() {
    eventually exited "$cpid"
    client_rc=0; wait "$cpid" || client_rc=$?
    cpid=
    eventually exited "$spid"
    server_rc=0; wait "$spid" || server_rc=$?
    spid=
    exec 3>&- 4>&-
}

# Neither endpoint has to wait for user input before displaying incoming lines.
start_server
start_client
printf '%s\n' '서버 먼저' 'second server line' >&3
eventually grep -Fxq 'peer> second server line' client.log
printf '%s\n' '클라이언트 응답' 'second client line' >&4
eventually grep -Fxq 'peer> second client line' server.log
printf '%s\n' '/quit' >&4
finish
[ "$server_rc:$client_rc" = 0:0 ] || fail "/quit did not close cleanly"
for side in server client; do
    grep -Fxq 'Connected: TLSv1.3' "$side.log" || fail "$side did not negotiate TLS 1.3"
done
for side in server client; do sed -n '/^peer> /p' "$side.log" > "$side.lines"; done
printf '%s\n' 'peer> 서버 먼저' 'peer> second server line' | cmp - client.lines || fail 'server messages changed'
printf '%s\n' 'peer> 클라이언트 응답' 'peer> second client line' | cmp - server.lines || fail 'client messages changed'

start_server
start_client
exec 3>&-
finish
[ "$server_rc:$client_rc" = 0:0 ] || fail 'server stdin EOF did not close cleanly'

mkdir other
"$openssl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 1 -subj /CN=wrong.invalid \
    -addext 'subjectAltName=DNS:wrong.invalid' \
    -addext 'basicConstraints=critical,CA:FALSE' -addext 'extendedKeyUsage=serverAuth' \
    -keyout other/server.key -out other/server.crt >cert.log 2>&1 || { cat cert.log >&2; exit 1; }
"$openssl" verify -CAfile other/server.crt -purpose sslserver -verify_hostname wrong.invalid \
    other/server.crt >>cert.log 2>&1 || { cat cert.log >&2; exit 1; }
# Same client trust store in both cases: first the issuer differs, then only the name.
start_server
export CHAT_CERT_DIR="$tmp/other"
start_client
finish
[ "$client_rc" -ne 0 ] || fail 'client accepted an untrusted certificate'

start_server
start_client
finish
[ "$client_rc" -ne 0 ] || fail 'client accepted a trusted certificate for a different host'
