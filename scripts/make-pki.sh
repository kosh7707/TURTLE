#!/usr/bin/env bash
# 정상 TLS 시험용 로컬 CA와 P-256 인증서를 만듭니다.
set -euo pipefail
out=${1:-build/pki}
mkdir -p "$out"
umask 077
openssl_bin=${OPENSSL:-openssl}
key() { "$openssl_bin" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$out/$1.key" >/dev/null 2>&1; }
key ca
"$openssl_bin" req -new -x509 -sha256 -days 3650 -key "$out/ca.key" -subj '/CN=TURTLE Test Root' -out "$out/ca.pem" -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign'
key intermediate
"$openssl_bin" req -new -sha256 -key "$out/intermediate.key" -subj '/CN=TURTLE Test Intermediate' -out "$out/intermediate.csr"
printf '%s\n' 'basicConstraints=critical,CA:TRUE,pathlen:0' 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid,issuer' > "$out/intermediate.ext"
"$openssl_bin" x509 -req -sha256 -days 3650 -in "$out/intermediate.csr" -CA "$out/ca.pem" -CAkey "$out/ca.key" -set_serial 2 -extfile "$out/intermediate.ext" -out "$out/intermediate.pem"
for role in server client; do
    key "$role"
    "$openssl_bin" req -new -sha256 -key "$out/$role.key" -subj "/CN=$role" -out "$out/$role.csr"
    usage=serverAuth; serial=3
    if [[ $role == client ]]; then usage=clientAuth; serial=4; fi
    printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' "extendedKeyUsage=$usage" 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid,issuer' > "$out/$role.ext"
    "$openssl_bin" x509 -req -sha256 -days 3650 -in "$out/$role.csr" -CA "$out/intermediate.pem" -CAkey "$out/intermediate.key" -set_serial "$serial" -extfile "$out/$role.ext" -out "$out/$role.pem"
    cat "$out/$role.pem" "$out/intermediate.pem" > "$out/$role-chain.pem"
    "$openssl_bin" verify -CAfile "$out/ca.pem" -untrusted "$out/intermediate.pem" "$out/$role.pem"
done
rm "$out/"*.csr "$out/"*.ext
