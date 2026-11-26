# 제출 예시

아래에서 사용할 예시를 직접 고르세요. TURTLE은 TLS 원본을 내려받거나 벤더를 자동 선택하지 않습니다. 포크나 다른 버전은 브리지와 레시피를 해당 API에 맞춰야 할 수 있습니다.

| 원본 (확인한 버전) | 소스 폴더 · 원본 빌드 도구 | 예시로 할 수 있는 일 |
|---|---|---|
| [OpenSSL 고정 커밋](https://github.com/openssl/openssl/commit/2d1c10a592677ff34cdf60bd59c431d835a1fc26) | `implementations/openssl/` · Perl, Make | [레시피](openssl/build.sh)와 [브리지](openssl/implementation.cpp). [첫 실행](../../../README.md#첫-실행)으로 S0부터 시작하세요. S0–S4 동작을 검증했으며 S2 서버의 Client Finished 수신 시간은 관측하지 못합니다. |
| [wolfSSL 5.9.4](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.4-stable) | `implementations/wolfssl/` · CMake | [레시피](wolfssl/build.sh)와 [브리지](wolfssl/implementation.cpp). 독립 빌드 확인. 서버 선송신(S2/S4) 미지원, 세션·실제 전송 관측 보강 필요. |
| [GnuTLS 3.8.14](https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.14.tar.xz) | `implementations/gnutls/` · `configure`가 포함된 배포본, Make, nettle/GMP/libtasn1/libidn2/p11-kit 등 (`configure` 진단 참조) | [레시피](gnutls/build.sh)와 [브리지](gnutls/implementation.cpp). 독립 빌드 확인. mTLS 또는 early start가 없는 연결은 서버 선송신 미지원, 세션·실제 전송 관측 보강 필요. |
| [Mbed TLS 4.3.0](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.3.0) | `implementations/mbedtls/` · CMake | [SDK 빌드 레시피](mbedtls/build.sh)만 제공합니다. 벤치마크용 브리지는 없습니다. |

압축을 푼 뒤 예를 들어 `implementations/gnutls/configure`처럼 원본 파일이 해당 폴더에 바로 보여야 합니다. 레시피와 브리지가 모두 있는 예시는 저장소 루트에서 아래처럼 선택하세요. `wolfssl`을 `gnutls`로 바꿔 쓸 수도 있습니다. 선택 도구는 편집한 파일을 덮어쓰지 않습니다.

```sh
job=$(mktemp -d)/build
tools/init-submission-example.sh wolfssl &&
  ./bench.sh --build-only --out "$job"
```

`"$job/build/bin/"`에 두 실행 파일이 생기면 빌드 단계가 성공한 것입니다. TLS 연결을 시도하려면 `./bench.sh --run-from "$job" --scenario S0`을 실행하세요. 빌드 성공이나 TLS 성공 자체가 측정 증거의 적격성을 보장하지는 않습니다. [결과 읽기](../../submission.md#결과).

### Mbed TLS 레시피만 실행

릴리스에서 하위 프로젝트를 포함한 `mbedtls-4.3.0.tar.bz2`를 받으세요(GitHub 자동 생성 소스 스냅샷이 아님). 릴리스의 해시를 확인하고 내용을 `implementations/mbedtls/`에 푼 뒤 저장소 루트에서 실행합니다.

```sh
job=$(mktemp -d)
mkdir "$job/work" "$job/prefix" &&
  (cd implementations && ../docs/examples/submissions/mbedtls/build.sh "$job/work" "$job/prefix") &&
  PKG_CONFIG_LIBDIR="$job/prefix/lib/pkgconfig" PKG_CONFIG_PATH= \
    pkg-config --cflags --libs mbedtls-sdk
```

이 명령은 TLS SDK만 설치합니다. TURTLE에서 실행하려면 레시피를 슬롯에 적용하고 [브리지를 직접 구현](../../submission.md#포팅)하세요. 이 예시는 선택 도구로 설치할 수 없습니다.
