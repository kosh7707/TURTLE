#!/usr/bin/env bash
# 준비된 의존성으로 CMake 구성과 빌드만 수행합니다.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

usage() {
    cat <<'EOF'
사용: scripts/build.sh [구성] [구현체] [-- -DCMAKE_옵션=값 ...]

구성                  기본 출력 폴더                 내용
module (기본)         build-module                   준비된 모듈·양쪽 엔드포인트·분석·조회
builtin [구현체]      build-builtin-구현체           내장 구현체의 양쪽 엔드포인트
client [구현체]       build-client-구현체            내장 구현체의 클라이언트만
server [구현체]       build-server-구현체            내장 구현체의 서버만
analysis              build-analysis                 보고서·해독 도구만
tests                 build-tests-independent        별도 시험 빌드 (시험 실행은 check.sh)

구현체 기본값: openssl
지원: openssl, wolfssl, mbedtls, bithac-baseline, bithac-cached, mlkem-c, mlkem-avx2

JOBS=4, TURTLE_DEPS_ROOT, TURTLE_BUILD_DIR로 병렬 수·의존성·출력을 지정합니다.
tests의 출력은 TURTLE_TEST_BUILD_DIR로 지정합니다.
TURTLE_BUILD_TYPE 기본값은 Release이며 tests는 Debug입니다.
상대 경로는 호출한 작업 폴더 기준, 기본 경로는 저장소 기준입니다.
의존성 준비: scripts/build-deps.sh all
빌드와 시험: REPEAT=1 scripts/check.sh
EOF
}

fail() { printf '%s\n' "$*" >&2; exit 2; }
case "${1:-}" in -h|--help) usage; exit 0 ;; esac
profile=${1:-module}
if (( $# )); then shift; fi
library=openssl
case "$profile" in
    builtin|client|server)
        if (( $# )) && [[ $1 != -- ]]; then library=$1; shift; fi
        case "$library" in
            openssl|wolfssl|mbedtls|bithac-baseline|bithac-cached|mlkem-c|mlkem-avx2) ;;
            *) fail "지원하지 않는 구현체: $library (--help 참고)" ;;
        esac ;;
    module|analysis|tests) ;;
    *) fail "지원하지 않는 빌드 구성: $profile (--help 참고)" ;;
esac
if (( $# )); then
    [[ $1 == -- ]] || fail '추가 CMake 옵션은 -- 뒤에 -D이름=값으로 지정하십시오.'
    shift
fi
deps=${TURTLE_DEPS_ROOT:-$root/.deps}
extra_options=()
for option in "$@"; do
    [[ $option == -D?*=* ]] || fail "지원하지 않는 CMake 옵션: $option (-D이름=값만 지원)"
    case "$option" in
        -DTURTLE_DEPS_ROOT=*|-DTURTLE_DEPS_ROOT:*=*) deps=${option#*=} ;;
        *) extra_options+=("$option") ;;
    esac
done
jobs=${JOBS:-4}
[[ $jobs =~ ^[1-9][0-9]*$ ]] || fail 'JOBS는 양의 정수여야 합니다.'
deps=$(realpath -m -- "$deps")
source=$root
build_type=${TURTLE_BUILD_TYPE:-Release}
default_build="$root/build-$profile"
client=ON server=ON lookup=OFF analysis=OFF modules=OFF linkage=builtin
openssl=OFF wolf=OFF mbed=OFF bithac=OFF mlkem=OFF
case "$profile" in
    module|tests)
        linkage=module modules=ON lookup=ON analysis=ON openssl=ON
        [[ ! -f "$deps/install/wolfssl-5.8.2-stable/include/wolfssl/ssl.h" ]] || wolf=ON
        [[ ! -f "$deps/install/mbedtls-3.6.4-pic/include/mbedtls/ssl.h" ]] || mbed=ON
        if [[ -f "$deps/install/bithac-baseline/lib/libwolfssl.a" && -f "$deps/install/bithac-cached/lib/libwolfssl.a" ]]; then bithac=ON; fi
        if [[ -f "$deps/install/mlkem-c/lib/libwolfssl.a" && -f "$deps/install/mlkem-avx2/lib/libwolfssl.a" ]]; then mlkem=ON; fi
        printf '기본 모듈: OpenSSL=ON wolfSSL=%s MbedTLS=%s BiTHaC=%s ML-KEM=%s\n' "$wolf" "$mbed" "$bithac" "$mlkem"
        ;;
    builtin|client|server)
        default_build="$root/build-$profile-$library"
        [[ $profile != client ]] || server=OFF
        [[ $profile != server ]] || client=OFF
        case "$library" in
            openssl) openssl=ON ;; wolfssl) wolf=ON ;; mbedtls) mbed=ON ;;
            bithac-*) bithac=ON ;; mlkem-*) mlkem=ON ;;
        esac ;;
    analysis) client=OFF server=OFF analysis=ON ;;
esac
if [[ $profile == tests ]]; then
    source="$root/tests"
    build_type=${TURTLE_BUILD_TYPE:-Debug}
    build=$(realpath -m -- "${TURTLE_TEST_BUILD_DIR:-$root/build-tests-independent}")
else
    build=$(realpath -m -- "${TURTLE_BUILD_DIR:-$default_build}")
fi
[[ $build != "$root" && $build != "$root/tests" ]] || fail '소스 폴더와 별도의 빌드 폴더를 지정하십시오.'
options=(-G Ninja "-DCMAKE_BUILD_TYPE=$build_type" -DTURTLE_WARNINGS_AS_ERRORS=ON
    "-DTURTLE_DEPS_ROOT=$deps" "-DTURTLE_ADAPTER_LINKAGE=$linkage" "-DTURTLE_IMPLEMENTATION=$library"
    "-DTURTLE_BUILD_CLIENT=$client" "-DTURTLE_BUILD_SERVER=$server" "-DTURTLE_BUILD_LOOKUP=$lookup"
    "-DTURTLE_BUILD_ANALYSIS=$analysis" -DTURTLE_WITH_INTERPRETER=ON "-DTURTLE_BUILD_MODULES=$modules"
    "-DTURTLE_WITH_OPENSSL=$openssl" "-DTURTLE_WITH_WOLFSSL=$wolf" "-DTURTLE_WITH_MBEDTLS=$mbed"
    "-DTURTLE_WITH_BITHAC=$bithac" "-DTURTLE_WITH_MLKEM=$mlkem")
printf '빌드: %s · 기본 %s · %s\n' "$profile" "$build_type" "$build"
if (( ${#extra_options[@]} )); then printf '추가 CMake 옵션: %s\n' "${extra_options[@]}"; fi
cmake -S "$source" -B "$build" "${options[@]}" "${extra_options[@]}"
cmake --build "$build" --parallel "$jobs"
