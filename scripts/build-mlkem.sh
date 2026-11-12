#!/usr/bin/env bash
# 같은 wolfSSL 커밋에서 ML-KEM 소스 파일의 최적화만 바꿉니다.
set -euo pipefail
project_root=$(cd "$(dirname "$0")/.." && pwd)
root=${TURTLE_DEPS_ROOT:-"$project_root/.deps"}
mkdir -p "$root"
root=$(cd "$root" && pwd)
source_dir="$root/src/wolfssl-mlkem"
commit=decea12e223869c8f8f3ab5a53dc90b69f436eb2
mkdir -p "$root/src" "$root/manifests"
if [[ ! -d $source_dir/.git ]]; then
    git init "$source_dir"
    git -C "$source_dir" remote add origin https://github.com/wolfSSL/wolfssl.git
    if [[ -d "$root/src/wolfssl-5.8.2-stable/.git" ]]; then
        git -C "$source_dir" fetch --depth 1 "$root/src/wolfssl-5.8.2-stable" "$commit"
    else
        git -C "$source_dir" fetch --depth 1 origin "$commit"
    fi
    git -C "$source_dir" checkout --detach FETCH_HEAD
fi
[[ $(git -C "$source_dir" rev-parse HEAD) == "$commit" ]]
patch_file="$project_root/implementations/mlkem/instrumentation.patch"
if patch --dry-run --force --silent --reverse -d "$source_dir" -p1 < "$patch_file" >/dev/null 2>&1; then
    :
else
    patch --dry-run --batch --forward --fuzz=0 -d "$source_dir" -p1 < "$patch_file"
    patch --batch --forward --fuzz=0 -d "$source_dir" -p1 < "$patch_file"
fi
for variant in c avx2; do
    enabled=OFF
    [[ $variant != avx2 ]] || enabled=ON
    flags='-DWOLFSSL_TLS13_MIDDLEBOX_COMPAT -DHAVE_SECRET_CALLBACK -DSHOW_SECRETS -DWOLFSSL_KEYLOG_EXPORT_WARNED -DWOLFSSL_GETRANDOM -Wno-error=stringop-overflow'
    cmake -S "$source_dir" -B "$root/build/mlkem-$variant" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_INSTALL_PREFIX="$root/install/mlkem-$variant" \
        "-DCMAKE_C_FLAGS=$flags" -DBUILD_SHARED_LIBS=OFF \
        -DWOLFSSL_TLS13=yes -DWOLFSSL_ECC=yes -DWOLFSSL_OPENSSLEXTRA=yes \
        -DWOLFSSL_SNI=yes -DWOLFSSL_SESSION_TICKET=yes -DWOLFSSL_KEYLOG_EXPORT=no \
        -DWOLFSSL_MLKEM=yes -DWOLFSSL_EXPERIMENTAL=yes "-DTURTLE_MLKEM_AVX2=$enabled" \
        -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no
    cmake --build "$root/build/mlkem-$variant" --parallel "${JOBS:-4}"
    cmake --install "$root/build/mlkem-$variant"
    cat > "$root/manifests/mlkem-$variant.txt" <<EOF
source=https://github.com/wolfSSL/wolfssl
commit=$commit
variant=$variant
cmake_build_type=Release
cmake_c_flags=$flags
cmake_options=PIC,static,TLS13,ECC,OPENSSLEXTRA,SNI,SESSION_TICKET,MLKEM,EXPERIMENTAL;examples=no;crypt_tests=no
source_local_definitions=wc_mlkem.c,wc_mlkem_poly.c:USE_INTEL_SPEEDUP,HAVE_INTEL_AVX1,HAVE_INTEL_AVX2;WC_MLKEM_NO_ASM only in c variant
EOF
done
python3 "$project_root/scripts/verify-mlkem-build.py" "$root"
sha256sum "$patch_file" > "$root/manifests/mlkem-instrumentation.sha256"
