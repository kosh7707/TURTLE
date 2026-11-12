#!/usr/bin/env bash
# 저자 공개 코드의 같은 커밋에서 캐시 없는 기준과 캐시 구현을 만듭니다.
set -euo pipefail
project_root=$(cd "$(dirname "$0")/.." && pwd)
root=${TURTLE_DEPS_ROOT:-"$project_root/.deps"}
mkdir -p "$root"
root=$(cd "$root" && pwd)
source_dir="$root/src/bithac"
commit=68ad825a37ef72cc1db4a67eb6d13275cc61f8aa
mkdir -p "$root/src" "$root/manifests"
if [[ ! -d $source_dir/.git ]]; then
    git init "$source_dir"
    git -C "$source_dir" remote add origin https://github.com/RWTH-SPICe/BiTHaC.git
    git -C "$source_dir" fetch --depth 1 origin "$commit"
    git -C "$source_dir" checkout --detach FETCH_HEAD
fi
[[ $(git -C "$source_dir" rev-parse HEAD) == "$commit" ]]
patch_file="$project_root/implementations/bithac/instrumentation.patch"
if patch --dry-run --force --silent --reverse -d "$source_dir" -p1 < "$patch_file" >/dev/null 2>&1; then
    :
else
    patch --dry-run --batch --forward --fuzz=0 -d "$source_dir" -p1 < "$patch_file"
    patch --batch --forward --fuzz=0 -d "$source_dir" -p1 < "$patch_file"
fi
for variant in baseline cached; do
    flags='-DWOLFSSL_TLS13_MIDDLEBOX_COMPAT -DHAVE_SECRET_CALLBACK -DSHOW_SECRETS -DWOLFSSL_GETRANDOM -Wno-error=stringop-overflow'
    if [[ $variant == cached ]]; then flags+=' -DWOLFSSL_CACHED_INFO -DWOLFSSL_SSC'; fi
    cmake -S "$source_dir" -B "$root/build/bithac-$variant" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_INSTALL_PREFIX="$root/install/bithac-$variant" \
        "-DCMAKE_C_FLAGS=$flags" -DBUILD_SHARED_LIBS=OFF \
        -DWOLFSSL_TLS13=yes -DWOLFSSL_ECC=yes -DWOLFSSL_OPENSSLEXTRA=yes \
        -DWOLFSSL_SNI=yes -DWOLFSSL_SESSION_TICKET=yes \
        -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no
    cmake --build "$root/build/bithac-$variant" --parallel "${JOBS:-4}"
    cmake --install "$root/build/bithac-$variant"
    cat > "$root/manifests/bithac-$variant.txt" <<EOF
source=https://github.com/RWTH-SPICe/BiTHaC
commit=$commit
reported_library_version=5.7.0
variant=$variant
cmake_build_type=Release
cmake_c_flags=$flags
cmake_options=PIC,static,TLS13,ECC,OPENSSLEXTRA,SNI,SESSION_TICKET;examples=no;crypt_tests=no
EOF
done
sha256sum "$patch_file" > "$root/manifests/bithac-instrumentation.sha256"
