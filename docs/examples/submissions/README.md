# 빌드 레시피 예시 (선택 사항)

**복사해서 출발점으로 쓰는 파일이지, TURTLE의 지원 벤더 목록이 아니다.** 아래에 없는 포크나 자체 TLS도 [같은 계약](../../build-contract.ko.md)을 충족하면 된다. `bench.sh`는 이 디렉터리를 탐색하거나 여기 있는 파일을 실행하지 않는다. TURTLE의 코어·링커에는 벤더 분기가 없다. 기존 SDK의 명시적 reference 경로는 별개다.

| 예시와 검증한 원본 | 필요한 원본 폴더 / 빌드 방법 | 함께 제공하는 것 |
|---|---|---|
| [OpenSSL 레시피](openssl/build.sh) · [고정한 4.2.0-dev 커밋](https://github.com/openssl/openssl/commit/2d1c10a592677ff34cdf60bd59c431d835a1fc26) | `openssl/` · 원본 Configure + Make (Perl 필요) | [연결 코드 예시](openssl/implementation.cpp). native 옵션 예: `-- no-asm`. |
| [wolfSSL 레시피](wolfssl/build.sh) · [v5.9.4-stable](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.4-stable) | `wolfssl/` · CMake build/install | [연결 코드 예시](wolfssl/implementation.cpp). CMake 옵션은 각각 하나의 `-D이름=값` 인자. |
| [Mbed TLS 레시피](mbedtls/build.sh) · [4.3.0 릴리스](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.3.0) | `mbedtls/` · 공식 완전한 릴리스 + CMake | **네이티브 SDK 예시만** 제공. [소스 확보·단독 실행·소비 메타데이터·PQ 범위](mbedtls/README.md). 보드 포팅이나 PQTLS 실험 예시가 아니다. |
| [GnuTLS 레시피](gnutls/build.sh) · [3.8.14 배포 소스](https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.14.tar.xz) | `gnutls/` · configure가 들어 있는 배포본 + Make 및 해당 버전의 개발 의존성 | [연결 코드 예시](gnutls/implementation.cpp). 다른 원본 빌드 시스템도 같은 방식으로 소비된다는 대조군이다. |

폴더 이름은 **이 레시피들**의 상대경로다. 직접 작성하는 레시피는 다른 이름을 써도 된다. 기존 연결 코드가 연구자의 포크에서 달라진 API나 인증 구성을 알아서 따라가는 것은 아니다. 예시가 추가·삭제되어도 프레임워크 계약은 바뀌지 않는다.

GnuTLS 예시는 이미 `configure`가 생성된 배포본을 사용했다. 이 구성의 호스트에는 nettle/hogweed, GMP, libtasn1, libidn2, p11-kit 등의 개발 파일이 있었다. 선택 기능에 따라 달라지므로 `configure` 진단을 따른다. 이들은 **제출한 GnuTLS의** 원본 빌드 의존성이지 TURTLE 코어의 의존성이 아니다.

### 목록에 없는 구현체라면

기존 방법이 예를 들어 **작업 디렉터리에서** `native-build --install-to 경로 [옵션…]`를 실행하는 것이라면, 연결에 필요한 레시피 모양은 아래와 같다. `native-build`는 TURTLE 명령이 아니다. 자기 프로젝트의 실제 명령으로 바꾼다.

```sh
#!/bin/sh
set -eu
work=$1 prefix=$2
shift 2
src=$(CDPATH='' cd -- ./my-source && pwd -P)
cd "$work"
"$src/native-build" --install-to "$prefix" "$@"
```

이 형태만으로 충분한 조건은 그 원본 명령이 **같은 구성의 헤더·공유 라이브러리·완전한 소비용 메타데이터**를 이미 설치한다는 것이다. 사용 정보가 빠진 프로젝트만 그 부분을 보완한다. 이 스크립트 안에서 `implementation.cpp`나 두 main을 빌드하지 않는다.

예컨대 자체 빌드가 `include/`와 `lib/libengine.so`를 사설 prefix에 설치하지만 **사용 메타데이터는 전혀 내지 않는** 작은 프로젝트라면, 레시피 끝에서 다음처럼 내보낼 수 있다. 여기서는 버전이 1.0이고 추가 공개 플래그·의존성이 없다고 가정한다. 실제 제출에서는 원본 빌드가 정한 값으로 작성한다.

```sh
mkdir -p "$prefix/lib/pkgconfig"
cat > "$prefix/lib/pkgconfig/engine.pc" <<'PC'
prefix=${pcfiledir}/../..
Name: engine
Description: Public interface of the submitted engine
Version: 1.0
Cflags: -I${prefix}/include
Libs: -L${prefix}/lib -lengine
PC
```

이는 사용 정보가 **없을 때만** 필요한 예다. 이미 정상적인 사용 정보를 제공하는 구현체에 이 파일까지 중복해서 만들지 않는다.

### 첫 사용: 새 슬롯에 명시적으로 선택하기

저장소 루트에서 시작한다. 예를 들어 **새** OpenSSL 소스 폴더를 준비하려면 아래와 같이 한다. 이미 연구 중인 소스가 있다면 clone/checkout하지 말고 그 소스를 사용한다. 포크를 예시 버전으로 되돌릴 필요는 없다.

```sh
git clone https://github.com/openssl/openssl.git implementations/openssl &&
git -C implementations/openssl checkout --detach 2d1c10a592677ff34cdf60bd59c431d835a1fc26
```

원본이 준비되면 아래처럼 OpenSSL을 **명시적으로 선택**한다. 도구는 Git이 없는 소스 배포본에서도 작동한다. 대상 두 파일이 없거나 배포된 시작 파일과 바이트가 같을 때만 설치하며, 수정한 파일·심볼릭 링크는 덮어쓰지 않는다. 두 파일 중 하나라도 구성하지 못하면 시작하지 않는다. 원본 폴더에는 쓰지 않는다.

```sh
tools/init-submission-example.sh openssl && ./bench.sh --build-only
```

wolfSSL·GnuTLS는 원본을 표의 위치에 두고 이름을 각각 `wolfssl`, `gnutls`로 바꾼다. Mbed TLS는 레시피만 있어 두 파일 설치가 거부된다. 그 경우 [Mbed TLS 안내](mbedtls/README.md)를 참고해 브리지를 직접 작성한다. 이미 수정한 슬롯이라면 덮어쓰기 명령 대신 예시와 직접 비교한다. 아직 갖고 있지 않은 원본을 이 도구가 내려받지는 않는다.

성공 기준은 출력된 결과 디렉터리 안의 `build/bin/client`와 `build/bin/server`의 링크다. 여기까지는 doctor·예열·성능 표본이 없다. 실행할 때만 `./bench.sh --resume "$job"`을 사용한다(`job`에는 출력된 경로를 넣는다). 원본 옵션을 지정했다면 재개 시에도 동일하게 `-- …`를 준다. 성능이 아니라 원본 빌드가 문제라면 먼저 `build/native.log`를 본다.
