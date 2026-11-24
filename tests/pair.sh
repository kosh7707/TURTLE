#!/bin/sh
# External endpoints are local test fixtures. Only the compiled role-pair test uses TCP.
set -eu
bench=$1
scratch=$(mktemp -d "${TMPDIR:-/tmp}/turtle-external.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"
provider='fork with spaces;literal'
mkdir "$provider" tools
# Restrict the test PATH to ordinary shell utilities.
for tool in basename cat chmod cp cut date dirname env expr grep head kill ln \
            mkdir mkfifo mktemp mv od paste ps pwd rm rmdir sed sh sleep sort tail tr wc; do
    path=$(command -v "$tool") || continue
    case "$path" in /*) ln -s "$path" "tools/$tool" ;; esac
done
profile="$provider/endpoints.json"

cat > "$profile" <<'JSON'
{
  "server": ["./my server"],
  "client": ["./my client", "127.0.0.1:{port}/{port}", "", "a b;$(: > SHOULD_NOT_EXIST)", "quote:\" slash:\\ glob:*", "trailing\n", "한글\ud83d\ude42"]
}
JSON
cat > "$provider/my server" <<'SH'
#!/bin/sh
set -eu
printf 'READY 4242\n'
IFS= read -r msg < done
[ "$msg" = done ]
echo "external server finished"
SH
cat > "$provider/my client" <<'SH'
#!/bin/sh
set -eu
[ "$#" -eq 6 ]
[ "$1" = '127.0.0.1:4242/4242' ]
[ "$2" = '' ]
[ "$3" = 'a b;$(: > SHOULD_NOT_EXIST)' ]
[ "$4" = 'quote:" slash:\ glob:*' ]
[ "$5" = 'trailing
' ]
[ "$6" = '한글🙂' ]
echo done > done
echo "external client finished"
SH
chmod +x "$provider/my server" "$provider/my client"
mkfifo "$provider/done"

launch() {
    mkdir -p "$scratch/$1"; oc=$(mktemp -d "$scratch/$1/parent.XXXXXX");
    PATH="$scratch/tools" "$bench" "$profile" "$oc/run"
}
has_field() {
    grep -Eq "\"$2\"[[:space:]]*:[[:space:]]*\"$3\"" "$1"
}

launch good
launch good
set -- good/*/run/run.json
[ "$#" -eq 2 ]
for report do
    has_field "$report" mode external
    has_field "$report" status ok
    grep -qx 'external client finished' "${report%/*}/client.log"
    grep -qx 'external server finished' "${report%/*}/server.log"
done
[ ! -f "$provider/SHOULD_NOT_EXIST" ]

cat > "$provider/my server" <<'SH'
#!/bin/sh
echo "$$" > server.pid
echo 'READY 4242'
exec sleep 25
SH
printf '#!/bin/sh\nexit 7\n' > "$provider/my client"
if launch client-fails; then echo 'unexpected success for failing client' >&2; exit 1; fi
has_field client-fails/*/run/run.json status failed
if kill -0 "$(cat "$provider/server.pid")" 2>/dev/null; then
    echo 'launcher left a server behind' >&2; exit 1
fi

# The preceding run has no setsid. When available, also exercise a foreground
# wrapper with a live child in the role's private process group.
if command -v setsid >/dev/null 2>&1; then
    ln -s "$(command -v setsid)" tools/setsid
    cat > "$provider/my server" <<'SH'
#!/bin/sh
sleep 25 &
echo "$!" > child.pid
echo 'READY 4242'
wait
SH
    if launch group-fails; then echo 'unexpected success for failing client' >&2; exit 1; fi
    has_field group-fails/*/run/run.json status failed
    child=$(cat "$provider/child.pid")
    # An orphan may briefly be a zombie: it is dead even if kill -0 succeeds.
    for attempt in first last; do
        case $(ps -o stat= -p "$child" 2>/dev/null) in ''|*Z*) break ;; esac
        if [ "$attempt" = last ]; then
            kill -s KILL "$child" 2>/dev/null || :
            echo 'launcher left a live server descendant behind' >&2; exit 1
        fi
        sleep 1
    done
fi

printf '#!/bin/sh\necho "READY 99999"\n' > "$provider/my server"
printf '#!/bin/sh\n: > client-started\n' > "$provider/my client"
if launch bad-ready; then echo 'unchecked READY port' >&2; exit 1; fi
has_field bad-ready/*/run/run.json status failed
[ ! -e "$provider/client-started" ]

# An invalid argv must fail before either role starts.
printf '#!/bin/sh\n: > server-started\n' > "$provider/my server"
printf '%s\n' '{"server":["./my server"],"client":[null,"{port}"]}' > "$profile"
if launch bad-json; then echo 'unchecked argv type' >&2; exit 1; fi
has_field bad-json/*/run/run.json status failed
[ ! -e "$provider/server-started" ]
"$bench" "$scratch/mock"
grep -Eq '^mock client: S0 matched \(not TLS\); before_send=[1-9][0-9]* after_receive=[1-9][0-9]*$' mock/client.log
grep -Eq '^mock server: S0 matched \(not TLS\); before_send=[1-9][0-9]* after_receive=[1-9][0-9]*$' mock/server.log
grep -Eq '"performance_eligible":[[:space:]]*false' mock/run.json
before=$(cksum mock/run.json)
if "$bench" "$scratch/mock"; then echo 'reused an output directory' >&2; exit 1; fi
[ "$before" = "$(cksum mock/run.json)" ]
for invalid in '{"server":["./my server"],"client":["x","{port}"],"client":["y","{port}"]}' \
               '{"server":["./my server"],"client":["x","{port}\u0000"]}' \
               '{"server":["./my server"],"client":["x"]}'; do
    printf '%s\n' "$invalid" > "$profile"
    if launch malformed; then echo 'accepted malformed role profile' >&2; exit 1; fi
    [ ! -e "$provider/server-started" ]
done
