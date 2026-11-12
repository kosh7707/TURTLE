#!/usr/bin/env bash
# TLS 비교에 쓰는 판과 설정을 고정합니다. 시험 실행은 이 스크립트를 부르지 않습니다.
set -euo pipefail
project_root=$(cd "$(dirname "$0")/.." && pwd)
root=${TURTLE_DEPS_ROOT:-"$(cd "$(dirname "$0")/.." && pwd)/.deps"}
mkdir -p "$root"
root=$(cd "$root" && pwd)
jobs=${JOBS:-4}
selection=${1:-all}
mkdir -p "$root/downloads" "$root/src" "$root/build" "$root/install"
mkdir -p "$root/manifests"
fetch() {
    local url=$1 path=$2 hash=$3
    if [[ ! -f $path ]]; then curl --fail --location --retry 2 "$url" -o "$path"; fi
    printf '%s  %s\n' "$hash" "$path" | sha256sum --check -
}
instrument() {
    local name=$1 source=$2
    local file="$project_root/implementations/$name/instrumentation.patch"
    if patch --dry-run --force --silent --reverse -d "$source" -p1 < "$file" >/dev/null 2>&1; then
        : # Already applied exactly.
    elif patch --dry-run --batch --silent --forward -d "$source" -p1 < "$file"; then
        patch --batch --forward -d "$source" -p1 < "$file"
    else
        echo "Source does not match the pinned TURTLE instrumentation patch: $name" >&2
        return 1
    fi
    sha256sum "$file" > "$root/manifests/$name-instrumentation.sha256"
}
openssl_build() {
    local archive="$root/downloads/openssl-3.5.4.tar.gz" src="$root/src/openssl-3.5.4"
    fetch https://www.openssl.org/source/openssl-3.5.4.tar.gz "$archive" 967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99
    [[ -d $src ]] || tar -xf "$archive" -C "$root/src"
    instrument openssl "$src"
    (cd "$src"; ./Configure --prefix="$root/openssl" --libdir=lib shared no-tests
        make -j"$jobs"; make install_sw)
    cat >"$root/manifests/openssl-3.5.4.txt" <<EOF
version=3.5.4
sha256=967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99
configure=./Configure --prefix=$root/openssl --libdir=lib shared no-tests
EOF
}
wolfssl_build() {
    local src="$root/src/wolfssl-5.8.2-stable"
    if [[ ! -d $src/.git ]]; then
        git clone --depth 1 --branch v5.8.2-stable https://github.com/wolfSSL/wolfssl.git "$src"
    fi
    [[ $(git -C "$src" rev-parse HEAD) == decea12e223869c8f8f3ab5a53dc90b69f436eb2 ]]
    instrument wolfssl "$src"
    cmake -S "$src" -B "$root/build/wolfssl-5.8.2-stable" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$root/install/wolfssl-5.8.2-stable" \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        '-DCMAKE_C_FLAGS=-DWOLFSSL_TLS13_MIDDLEBOX_COMPAT -DHAVE_SECRET_CALLBACK -DSHOW_SECRETS -DWOLFSSL_KEYLOG_EXPORT_WARNED -DWOLFSSL_GETRANDOM -Wno-error=stringop-overflow' \
        -DBUILD_SHARED_LIBS=OFF -DWOLFSSL_TLS13=yes -DWOLFSSL_ECC=yes \
        -DWOLFSSL_OPENSSLEXTRA=yes -DWOLFSSL_KEYLOG_EXPORT=no -DWOLFSSL_SNI=yes \
        -DWOLFSSL_SESSION_TICKET=yes -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no
    cmake --build "$root/build/wolfssl-5.8.2-stable" --parallel "$jobs"
    cmake --install "$root/build/wolfssl-5.8.2-stable"
    cat >"$root/manifests/wolfssl-5.8.2-stable.txt" <<EOF
version=5.8.2-stable
commit=decea12e223869c8f8f3ab5a53dc90b69f436eb2
cmake_generator=Ninja
cmake_build_type=Release
cmake_c_flags=-DWOLFSSL_TLS13_MIDDLEBOX_COMPAT -DHAVE_SECRET_CALLBACK -DSHOW_SECRETS -DWOLFSSL_KEYLOG_EXPORT_WARNED -DWOLFSSL_GETRANDOM -Wno-error=stringop-overflow
cmake_options=-DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF -DWOLFSSL_TLS13=yes -DWOLFSSL_ECC=yes -DWOLFSSL_OPENSSLEXTRA=yes -DWOLFSSL_KEYLOG_EXPORT=no -DWOLFSSL_SNI=yes -DWOLFSSL_SESSION_TICKET=yes -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no
EOF
}
mbedtls_build() {
    local archive="$root/downloads/mbedtls-3.6.4.tar.bz2" src="$root/src/release-3.6.4"
    fetch https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.4/mbedtls-3.6.4.tar.bz2 "$archive" ec35b18a6c593cf98c3e30db8b98ff93e8940a8c4e690e66b41dfc011d678110
    if [[ ! -d $src ]]; then mkdir -p "$src"; tar -xf "$archive" --strip-components=1 -C "$src"; fi
    instrument mbedtls "$src"
    cmake -S "$src" -B "$root/build/mbedtls-3.6.4-pic" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_INSTALL_PREFIX="$root/install/mbedtls-3.6.4-pic" \
        '-DCMAKE_C_FLAGS=-DMBEDTLS_PLATFORM_MEMORY' \
        -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF \
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON
    cmake --build "$root/build/mbedtls-3.6.4-pic" --parallel "$jobs"
    cmake --install "$root/build/mbedtls-3.6.4-pic"
    cat >"$root/manifests/mbedtls-3.6.4.txt" <<EOF
version=3.6.4
sha256=ec35b18a6c593cf98c3e30db8b98ff93e8940a8c4e690e66b41dfc011d678110
cmake_generator=Ninja
cmake_build_type=Release
cmake_c_flags=-DMBEDTLS_PLATFORM_MEMORY
cmake_options=-DCMAKE_POSITION_INDEPENDENT_CODE=ON -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON
EOF
}
case "$selection" in
    openssl) openssl_build;;
    wolfssl) wolfssl_build;;
    mbedtls) mbedtls_build;;
    all) openssl_build; wolfssl_build; mbedtls_build;;
    *) echo "usage: TURTLE_DEPS_ROOT=... $0 [all|openssl|wolfssl|mbedtls]" >&2; exit 2;;
esac
printf 'Dependency root: %s\n' "$root"
