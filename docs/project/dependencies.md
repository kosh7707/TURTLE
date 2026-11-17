# 의존성 준비

프레임워크의 대상은 Linux다. C++20·CMake 3.20 이상·Ninja를 사용한다. 버전·공식 소스 URL·SHA-256·라이선스·빌드 옵션의 기준은 [dependencies.json](dependencies.json)이다. TLS 구현체의 의존성은 구현자가 선택하고 프레임워크 코어는 OpenSSL이나 wolfSSL을 링크하지 않는다.

| 의존성 | 역할 | 준비 기준 |
|---|---|---|
| nlohmann/json | 측정 밖 명세·JSON·JSONL 처리와 정수 보존 | 3.12.0, MIT |
| libpcap | C++ 수집기와 고전 pcap 읽기 | 1.10.6, BSD-3-Clause |
| Linux의 perf | 별도 CPU 표본 수집·심볼 해석 | 7.0.14 공식 소스, Python 연결 비활성 |
| iproute2·ethtool·sysctl | 네임스페이스·veth·netem 설정과 상태 기록 | 실제 실행 버전 기록 |
| sha256sum·readelf·ldd | 파일 해시·ELF build ID·연결 의존성 | Linux 설치 도구 |
| OpenSSL | 기준 구현과 버전 교체 검증 | 3.5.9 및 3.5.5 |
| wolfSSL | 두 번째 구현과 교차 연결 | 5.9.4 |

libpcap은 DBus·Bluetooth·USB·RDMA·netmap·libnl 기능을 끈 정적 빌드를 사용한다. Ethernet/IPv4 TCP 관측에 필요하지 않은 의존성을 추가하지 않는다. nlohmann/json은 헤더 라이브러리이며 구현자용 C 헤더에는 노출되지 않는다.

## 다운로드와 준비의 분리

선택적 Python 도구로 공식 소스를 한 번 받아 검증할 수 있다. 이 도구는 프레임워크 빌드나 실행에서 호출되지 않는다.

```sh
python3 tools/dependencies.py fetch all --cache .deps/cache
python3 tools/dependencies.py prepare all --cache .deps/cache --workspace .deps/prepared --jobs 4
```

`fetch`만 네트워크를 사용한다. `prepare`는 해시가 맞는 캐시만 읽고 각 의존성의 `source/`, `build/`, `install/`, `provenance.json`을 만든다. `all` 대신 `framework`, `tls`, `perf`를 선택할 수 있다. 로컬 빌드 도구로 C/C++ 컴파일러, Make, CMake, Ninja, pkg-config, flex, bison과 perf용 libelf·libdw 개발 파일을 준비한다. perf 소스의 PMU 테이블 생성에는 준비 단계의 Python이 사용될 수 있으나 생성된 perf는 Python 실행이나 libpython을 요구하지 않는다.

준비된 prefix를 CMake에 전달한다.

```sh
cmake -S . -B out/build/native -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$PWD/.deps/prepared/json-3.12.0/install;$PWD/.deps/prepared/libpcap-1.10.6/install" \
  -DTURTLE_IMPLEMENTATION_DIRS="$PWD/implementations/openssl;$PWD/implementations/wolfssl" \
  -DOPENSSL_ROOT_DIR="$PWD/.deps/prepared/openssl-3.5.9/install" \
  -DWOLFSSL_ROOT_DIR="$PWD/.deps/prepared/wolfssl-5.9.4/install"
cmake --build out/build/native
```

기설치 라이브러리나 직접 빌드한 prefix도 사용할 수 있다. 구성·빌드·CTest에서 자동 다운로드하거나 Python을 탐색하지 않는다. 현재 검증에서 직접 준비한 JSON·libpcap·perf의 prefix는 `.deps/native`이며 TLS는 `.deps/openssl-3.5.9/install` 등에서 선택했다. 설치 경로는 계약이 아니다.

## 수동 준비

소스 아카이브를 풀기 전에 잠금 목록의 SHA-256과 대조한다. JSON은 `JSON_BuildTests=OFF`로 CMake 설치하고, libpcap은 잠금 목록의 옵션으로 CMake 설치한다. 기본 OpenSSL 빌드는 Configure의 호스트 선택을 사용하며 플랫폼 이름을 소스 코드에 고정하지 않는다. wolfSSL은 ML-KEM·ML-DSA·Curve25519·SNI와 독립 ML-KEM을 활성화한다.

perf는 공식 Linux 소스의 `tools/perf`에서 다음처럼 빌드한다. 소스 트리에 빌드 산출물을 섞지 않는다.

```sh
mkdir -p out/perf-build
make -C SOURCE/tools/perf O="$PWD/out/perf-build/" -j4 \
  NO_LIBPYTHON=1 NO_LIBPERL=1 NO_LIBBPF=1 NO_LIBTRACEEVENT=1 \
  NO_LIBNUMA=1 NO_SLANG=1 NO_LIBBABELTRACE=1 NO_LIBPFM4=1 \
  NO_LIBDEBUGINFOD=1 WERROR=0
out/perf-build/perf --version
ldd out/perf-build/perf
```

ELF·DWARF 기능은 유지한다. 실제 연결 목록에 `libpython`이 없는지 확인하며 C++ 실행기는 Python이 연결된 perf를 거절한다. 시스템 perf 제한 값을 자동으로 바꾸거나 요청한 하드웨어 이벤트를 소프트웨어 이벤트로 대체하지 않는다.

## ARM64

`cmake/linux-arm64.cmake`는 GCC 교차 컴파일러를 선택한다. 컴파일러와 sysroot가 다른 환경에서는 별도 toolchain 파일을 제공할 수 있다. 대상 libpcap·TLS 라이브러리와 nlohmann/json prefix를 먼저 준비한다.

```sh
python3 tools/dependencies.py prepare framework --target arm64 \
  --cache .deps/cache --workspace .deps/arm64-prepared
python3 tools/dependencies.py prepare tls --target arm64 \
  --cache .deps/cache --workspace .deps/arm64-prepared
```

wolfSSL 5.9.4의 GCC 15 ARM64 빌드는 upstream AES 코드의 `stringop-overflow` 경고가 `-Werror`로 승격된다. 이 준비 경로는 `-Wno-error=stringop-overflow`로 해당 승격만 해제하고 경고를 남긴다. 원본 소스는 수정하지 않는다. 실제 보드 검증이 끝났다는 의미는 아니다.

perf의 교차 빌드는 대상용 libelf·libdw 등 개발 파일과 pkg-config 설정도 필요하다. 이번 ARM64 검증은 프레임워크·OpenSSL·wolfSSL ELF 빌드이며 보드의 perf·netem 실행은 별도다. 배포판별 amd64 패키지를 준비 경로에 고정하지 않는다.
