# 빌드 레시피 예시 (선택 사항)

**복사해서 출발점으로 쓰는 파일이지, TURTLE의 지원 벤더 목록이 아니다.** 아래에 없는 포크나 자체 TLS도 [같은 계약](../../build-contract.ko.md)을 충족하면 된다. `bench.sh`는 이 디렉터리를 탐색하거나 여기 있는 파일을 실행하지 않는다. TURTLE의 코어·링커에는 벤더 분기가 없다. 기존 SDK의 명시적 reference 경로는 별개다.

| 예시 및 확인한 소스 | 준비할 폴더와 원본 도구 | 권장 첫 실행과 한계 |
|---|---|---|
| [OpenSSL 레시피](openssl/build.sh) · [고정 4.2.0-dev 커밋](https://github.com/openssl/openssl/commit/2d1c10a592677ff34cdf60bd59c431d835a1fc26) | `implementations/openssl/` · Configure, Perl, Make | [기본 가이드대로 S0](../../../README.md#제출-구현으로-첫-실행). [브리지](openssl/implementation.cpp)에 S0–S4와 실제 전송 길이 계측이 있다. S2 서버의 CF 수신 시간은 제공하지 않는다. native 옵션 예: `-- no-asm`. |
| [wolfSSL 레시피](wolfssl/build.sh) · [v5.9.4-stable](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.4-stable) | `implementations/wolfssl/` · CMake build/install | 아래처럼 빌드부터 확인한다. [브리지](wolfssl/implementation.cpp)의 일반 핸드셰이크로 S0을 시도할 수 있으나 서버 인사를 요구하는 S2/S4는 명시적 미지원이다. 결과를 검증하려면 세션 사실과 실제 전송 계측을 추가한다. CMake 옵션은 각각 하나의 `-D이름=값` 인자다. |
| [GnuTLS 레시피](gnutls/build.sh) · [3.8.14 배포 소스](https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.14.tar.xz) | `implementations/gnutls/` · configure가 들어 있는 배포본, Make 및 버전별 개발 의존성 | 아래처럼 빌드부터 확인하고 S0부터 시도한다. [브리지](gnutls/implementation.cpp)는 mTLS의 서버 인사를 제공하지 않는다. 서버 인증에서도 native early start 플래그가 없으면 S2/S4는 미지원이다. 세션 사실과 실제 전송 계측 보강이 필요하다. |
| [Mbed TLS 레시피](mbedtls/build.sh) · [4.3.0 릴리스](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.3.0) | `implementations/mbedtls/` · 공식 완전한 릴리스, CMake | [네이티브 SDK만 빌드](mbedtls/README.md). 제출용 브리지가 없으므로 예시 선택 도구는 설치를 거부한다. |

OpenSSL은 실행까지 검증한 예시다. wolfSSL·GnuTLS의 증거는 독립 빌드에 한하며, 같은 버전에서 모든 런타임 시나리오가 통과한다는 뜻이 아니다.

폴더 이름은 **이 레시피들**의 상대경로다. 직접 작성하는 레시피는 다른 이름을 써도 된다. 기존 연결 코드가 연구자의 포크에서 달라진 API나 인증 구성을 알아서 따라가는 것은 아니다. 예시가 추가·삭제되어도 프레임워크 계약은 바뀌지 않는다.

GnuTLS 예시는 이미 `configure`가 생성된 배포본을 사용했다. 이 구성의 호스트에는 nettle/hogweed, GMP, libtasn1, libidn2, p11-kit 등의 개발 파일이 있었다. 선택 기능에 따라 달라지므로 `configure` 진단을 따른다. 이들은 **제출한 GnuTLS의** 원본 빌드 의존성이지 TURTLE 코어의 의존성이 아니다.

### 예시 선택 후 빌드 확인

준비한 원본은 표의 위치에 둔다. 공식 아카이브를 쓴다면 최상위 디렉터리 한 겹을 벗겨, 예를 들어 `implementations/openssl/Configure`나 `implementations/gnutls/configure`가 바로 보이게 푼다. 기존 연구 소스는 checkout이나 추출로 덮지 않는다. 다른 버전 또는 포크는 브리지와 레시피를 그 API에 맞춰야 할 수 있다.

예를 들어 받은 OpenSSL 소스 아카이브에 대해, 실제 파일 경로를 넣고 **아직 없는** 디렉터리에 푼다.

```sh
archive=/path/to/openssl-source.tar.gz
mkdir implementations/openssl &&
  tar -xf "$archive" --strip-components=1 -C implementations/openssl
```

새 슬롯에서 저장소 루트로 이동하여 사용할 예시 이름을 지정한다. 아래는 wolfSSL이다. GnuTLS라면 `gnutls`로 바꾼다. 이 도구는 원본을 내려받지 않으며 수정한 두 제출 파일을 덮어쓰지 않는다.

```sh
job=$(mktemp -d)/build
tools/init-submission-example.sh wolfssl &&
  ./bench.sh --build-only --out "$job"
```

`build/bin/client`와 `build/bin/server`가 생기면 **빌드**가 성공한 것이다. 이 단계에서 TLS 연결이나 측정은 없다. 빌드가 실패하면 `"$job/build/native.log"`의 첫 원인을 찾는다. 완료한 빌드로 S0을 시도하려면 `./bench.sh --run-from "$job" --scenario S0`을 실행한다. 판정과 수치는 [CSV 결과 안내](../../submission.md#results)에서 확인한다.

예시가 없는 TLS 구현은 [빌드 계약](../../build-contract.ko.md)에 맞춰 원본 빌드를 호출하고, 사설 SDK에 필요한 `.pc`가 없을 때만 소비자 메타데이터를 추가한다. 레시피에서 두 역할이나 브리지를 직접 빌드하지 않는다.
