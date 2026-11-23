#!/bin/sh
# Disposable benchmark CA; refuses to replace an existing directory.
set -eu
umask 077
dir=${1:?usage: issue-test-leaves.sh NEW_DIRECTORY [openssl]}
ossl=${2:-openssl}
mkdir -p "$(dirname "$dir")"
mkdir "$dir"
cd "$dir"
"$ossl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 2 \
    -config /dev/null -subj "/CN=TURTLE test CA" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout ca.key -out ca.crt
for role in server client; do
    subject="$role"; serial=2
    if [ "$role" = server ]; then subject=localhost; serial=1; fi
    "$ossl" req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -config /dev/null \
        -subj "/CN=$subject" -keyout "$role.key" -out "$role.csr"
    {
        echo 'basicConstraints=critical,CA:FALSE'
        echo 'keyUsage=critical,digitalSignature'
        echo "extendedKeyUsage=${role}Auth"
        if [ "$role" = server ]; then echo 'subjectAltName=DNS:localhost'; fi
    } > "$role.ext"
    "$ossl" x509 -req -in "$role.csr" -CA ca.crt -CAkey ca.key -set_serial "$serial" \
        -days 2 -extfile "$role.ext" -out "$role.crt"
done
