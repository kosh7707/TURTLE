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
validity_days=3650
backdate_seconds=300
issued_at=$(date -u +%s)
# 발급 중 실제 시계가 잠깐 뒤로 조정되어도 정상 인증서가 미래에 시작하지 않도록 5분 앞서 시작한다.
not_before=$(date -u -d "@$((issued_at-backdate_seconds))" +%Y%m%d%H%M%SZ)
not_after=$(date -u -d "@$((issued_at+validity_days*86400))" +%Y%m%d%H%M%SZ)
ca_state=$(mktemp -d)
trap 'rm -rf -- "$ca_state"' EXIT
mkdir "$ca_state/certs"
: > "$ca_state/index"
cat > "$ca_state/config" <<EOF
[ ca ]
default_ca = signing_ca
[ signing_ca ]
database = $ca_state/index
new_certs_dir = $ca_state/certs
serial = $ca_state/serial
default_md = sha256
policy = subject_policy
[ subject_policy ]
commonName = supplied
EOF
sign() {
    local name=$1 issuer=$2 serial=$3
    printf '%02X\n' "$serial" > "$ca_state/serial"
    "$openssl_bin" ca -batch -notext -config "$ca_state/config" -startdate "$not_before" -enddate "$not_after" \
        -in "$out/$name.csr" -cert "$out/$issuer.pem" -keyfile "$out/$issuer.key" \
        -extfile "$out/$name.ext" -extensions extensions -out "$out/$name.pem"
}
key ca
"$openssl_bin" req -new -sha256 -key "$out/ca.key" -subj '/CN=TURTLE Test Root' -out "$out/ca.csr"
printf '%s\n' '[extensions]' 'basicConstraints=critical,CA:TRUE,pathlen:2' 'keyUsage=critical,keyCertSign,cRLSign' > "$out/ca.ext"
printf '01\n' > "$ca_state/serial"
"$openssl_bin" ca -batch -selfsign -notext -config "$ca_state/config" -startdate "$not_before" -enddate "$not_after" \
    -in "$out/ca.csr" -keyfile "$out/ca.key" -extfile "$out/ca.ext" -extensions extensions -out "$out/ca.pem"
issuer=ca
chain_file="$out/intermediates.pem"
: > "$chain_file"
for ((level=1; level<chain_length; ++level)); do
    name="intermediate-$level"
    key "$name"
    "$openssl_bin" req -new -sha256 -key "$out/$name.key" -subj "/CN=TURTLE Test Intermediate $level" -out "$out/$name.csr"
    printf '%s\n' '[extensions]' "basicConstraints=critical,CA:TRUE,pathlen:$((chain_length-level-1))" 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid,issuer' > "$out/$name.ext"
    sign "$name" "$issuer" "$((10+level))"
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
    printf '%s\n' '[extensions]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' "extendedKeyUsage=$usage" 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid,issuer' > "$out/$role.ext"
    sign "$role" "$issuer" "$serial"
    cat "$out/$role.pem" "$chain_file" > "$out/$role-chain.pem"
    if ((chain_length > 1)); then
        "$openssl_bin" verify -CAfile "$out/ca.pem" -untrusted "$chain_file" "$out/$role.pem"
    else
        "$openssl_bin" verify -CAfile "$out/ca.pem" "$out/$role.pem"
    fi
done
rm "$out/"*.csr "$out/"*.ext
