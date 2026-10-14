#!/usr/bin/env bash
# 정상 TLS 시험용 로컬 CA와 P-256 인증서를 만듭니다.
set -euo pipefail
out=${1:-build/pki}
algorithm=${2:-ecdsa}
chain_length=${3:-2}
case "$algorithm" in ecdsa|rsa|ed25519) ;; *) echo "algorithm: ecdsa, rsa, ed25519" >&2; exit 2;; esac
case "$chain_length" in 1|2|3) ;; *) echo "chain length: 1, 2, 3 (leaf included, root excluded)" >&2; exit 2;; esac
mkdir -p "$out"
umask 077
openssl_bin=${OPENSSL:-openssl}
key() { "$openssl_bin" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$out/$1.key" >/dev/null 2>&1; }
key ca
"$openssl_bin" req -new -x509 -sha256 -days 3650 -key "$out/ca.key" -subj '/CN=TURTLE Test Root' -out "$out/ca.pem" -addext 'basicConstraints=critical,CA:TRUE,pathlen:2' -addext 'keyUsage=critical,keyCertSign,cRLSign'
issuer=ca
chain_file="$out/intermediates.pem"
: > "$chain_file"
for ((level=1; level<chain_length; ++level)); do
    name="intermediate-$level"
    key "$name"
    "$openssl_bin" req -new -sha256 -key "$out/$name.key" -subj "/CN=TURTLE Test Intermediate $level" -out "$out/$name.csr"
    printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:$((chain_length-level-1))" 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid,issuer' > "$out/$name.ext"
    "$openssl_bin" x509 -req -sha256 -days 3650 -in "$out/$name.csr" -CA "$out/$issuer.pem" -CAkey "$out/$issuer.key" -set_serial "$((10+level))" -extfile "$out/$name.ext" -out "$out/$name.pem"
    cat "$out/$name.pem" "$chain_file" > "$out/chain.tmp"
    mv "$out/chain.tmp" "$chain_file"
    issuer=$name
done
for role in server client; do
    case "$algorithm" in
        ecdsa) key "$role";;
        rsa) "$openssl_bin" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$out/$role.key" >/dev/null 2>&1;;
        ed25519) "$openssl_bin" genpkey -algorithm ED25519 -out "$out/$role.key";;
    esac
    "$openssl_bin" req -new -sha256 -key "$out/$role.key" -subj "/CN=$role" -out "$out/$role.csr"
    usage=serverAuth; serial=3
    if [[ $role == client ]]; then usage=clientAuth; serial=4; fi
    printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' "extendedKeyUsage=$usage" 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid,issuer' > "$out/$role.ext"
    "$openssl_bin" x509 -req -sha256 -days 3650 -in "$out/$role.csr" -CA "$out/$issuer.pem" -CAkey "$out/$issuer.key" -set_serial "$serial" -extfile "$out/$role.ext" -out "$out/$role.pem"
    cat "$out/$role.pem" "$chain_file" > "$out/$role-chain.pem"
    if ((chain_length > 1)); then
        "$openssl_bin" verify -CAfile "$out/ca.pem" -untrusted "$chain_file" "$out/$role.pem"
    else
        "$openssl_bin" verify -CAfile "$out/ca.pem" "$out/$role.pem"
    fi
done
rm "$out/"*.csr "$out/"*.ext
