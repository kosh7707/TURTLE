# TURTLE

TURTLE은 인증서 기반 TLS 1.3 전체 핸드셰이크와 암호화된 `ping`·`pong`을 실행하고, 클라이언트와 서버의 비용을 공개 호출·TLS 레코드·TCP 바이트에 연결하는 C/C++ 벤치마크 프레임워크입니다. TURTLE은 약어가 아닌 프로젝트 이름입니다.

TLS 라이브러리가 생성한 레코드 앞에 방향별 번호가 있는 4바이트 TU 프레임을 붙이고, 수신 라이브러리에 전달하기 전에 제거합니다. TCP 패킷마다 헤더를 붙이는 방식이 아닙니다. 라이브러리 내부 수정·핸드셰이크 메시지 콜백·복호화 없이 실제 전송 바이트와 재전송을 연결합니다.

[설계와 레코드 프레임 기반 측정 방법론](docs/project/OVERVIEW.md)은 프레임 위치, 증분 상태, 시간 경계, 바이트 대응과 해석 한계를 자세히 설명합니다. [현재 결정](docs/project/DECISIONS.md), [검증 결과](docs/project/validation.md)도 함께 볼 수 있습니다.

## 실행 환경과 부품

대상은 Linux의 IPv4 TCP와 블로킹 I/O입니다. ARM64 교차 빌드를 검증하며 실제 보드 실행은 별도 검증입니다. 표본마다 클라이언트·서버를 새 프로세스로 시작하고, 각 프로세스는 컨텍스트 하나와 연결 하나를 사용합니다.

| 위치 | 책임 |
|---|---|
| `include/turtle/` | 구현자용 C 함수표·불투명 상태·전송 계약 |
| `implementations/` | OpenSSL·wolfSSL 공개 API 연결과 설정 |
| `src/endpoint`, `src/run` | 엔드포인트 진입점과 TLS 호출 수명 |
| `src/frame`, `src/net`, `src/measure` | 프레임·소켓·시계·사건·성능 카운터 |
| `src/artifact` | 측정 뒤 JSON·JSONL·바이트 스트림 기록 |
| `src/process`, `src/control` | 자식 프로세스, 파이프, 반복, 네트워크 자원 |
| `src/capture`, `src/analysis`, `src/profiling` | libpcap, 구간·패킷·카운터·CPU 표본 분석 |
| `tests/` | 별도 CMake/CTest의 C·C++ 시험 |
| `tools/` | 선택적 보고서·의존성 준비·개발 검증 유틸 |

실행·수집·원자료 해석·유효성 판정은 C++입니다. 프레임워크의 구성·빌드·필수 테스트·실행·분석에는 Python이 필요하지 않습니다. Python 보고서와 준비 도구는 `tools/`에서 별도로 실행합니다.

## 의존성 준비와 빌드

C++20 컴파일러, CMake 3.20 이상, Ninja, nlohmann/json 3.12.0과 libpcap 1.10.6을 준비합니다. 네트워크 실행은 iproute2의 `ip`·`tc`, `ethtool`, `sysctl`, veth·netem 지원과 해당 권한을 사용합니다. 출처 해시는 `sha256sum`, ELF 출처와 CPU 표본은 `readelf`·`ldd`·Python을 연결하지 않은 공식 perf를 사용합니다. tcpdump는 실행 의존성이 아닙니다.

[의존성 문서](docs/project/dependencies.md)에 고정 출처·체크섬·라이선스·수동 준비와 선택적 도구 사용법이 있습니다. 아래 예제는 준비한 라이브러리를 `.deps/native`, TLS 라이브러리를 각 `.deps/<이름>-<버전>/install`에서 선택합니다. 설치 위치는 자유롭게 바꿀 수 있습니다.

```sh
cmake -S . -B out/build/native -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$PWD/.deps/native" \
  -DTURTLE_IMPLEMENTATION_DIRS="$PWD/implementations/openssl;$PWD/implementations/wolfssl" \
  -DOPENSSL_ROOT_DIR="$PWD/.deps/openssl-3.5.9/install" \
  -DWOLFSSL_ROOT_DIR="$PWD/.deps/wolfssl-5.9.4/install"
cmake --build out/build/native
```

구현체 선택을 생략하면 TLS 라이브러리를 탐색하지 않고 프레임워크만 빌드합니다. 외부 CMake·설치 라이브러리·Make 기반 등록은 [빌드 계약](docs/project/build.md)을 따릅니다. `turtle::endpoint`를 연결한 구현체는 내부 헤더를 포함하지 않습니다.

```sh
cmake --install out/build/native --prefix "$PWD/out/install"
out/install/bin/turtle --help
```

설치된 CLI는 런타임에 소스 트리나 `tools/`를 찾지 않습니다.

## 실제 실행

예제용 인증서를 준비합니다. 임시 인증서 자체를 클라이언트의 신뢰 대상으로 지정하는 예이며, 통합 시험은 별도 CA와 서버 인증서 체인을 생성합니다.

```sh
mkdir -p out/certificates
.deps/openssl-3.5.9/install/bin/openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:P-256 -noenc -days 2 -config /dev/null \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -addext basicConstraints=critical,CA:FALSE \
  -keyout out/certificates/server.key -out out/certificates/server.crt
sudo out/build/native/turtle run examples/compare.json out/runs/comparison
out/build/native/turtle analyze out/runs/comparison
```

관리자 권한 대신 지원되는 환경의 사용자 네임스페이스를 준비할 수도 있습니다. `tools/netns-exec.sh`는 그때만 선택적으로 사용하는 래퍼입니다. 일반 loopback 명세는 네트워크 관측을 `not_collected`로 남깁니다.

명세는 `configurations[]`의 `client.binary`, `server.binary`, `args`, 선택적 `env`를 지정합니다. 구현체 인자는 해석하지 않고 전달하며 상대 경로는 호출한 작업 디렉터리 기준입니다. 출처로 남길 입력은 `inputs`에 명시합니다. 출력 경로는 새 디렉터리여야 합니다.

기본값은 구성당 30회, 순서 seed 0입니다. 반복 묶음 안에서 구성 순서를 섞고 실제 순서를 저장합니다. 기준 실행도 같은 세 네임스페이스·두 veth 토폴로지에서 실행합니다. 방향별 netem은 중간 네임스페이스에서 각 수신 측으로 나가는 인터페이스에 설정합니다. 수집기는 TCP 연결 전에 양쪽에서 READY를 보내고, 엔드포인트 준비 장벽 뒤 TLS를 시작합니다.

## 원자료·분석·보고서

```text
manifest.json                  명세·실행 순서·출처·모든 시도와 실패
analysis.json                  실행 전체의 계측 완료 여부
attempts/00000/
  processes.json, network.json
  client.pcap, server.pcap
  client.capture.json, server.capture.json
  client/, server/
    endpoint.json, events.jsonl, counters.json
    tls_send.bin, tls_receive.bin
    wire_send.bin, wire_receive.bin
    stderr.log, control.log
    profile.json, perf.data, symbols/   CPU 표본 수집 시
  analysis.json                레코드·사건·패킷 대응, 지표·단위·유효성
```

정수 시각·카운터·바이트 범위를 보존합니다. 실제 0, `not_collected`, `unsupported`, `missing`은 서로 다릅니다. JSON 작성은 측정 뒤에 수행합니다. 원자료 형식은 엔드포인트 v3·사건 v2·카운터 v1이며, 파생 분석은 `turtle.attempt-report.v4`입니다.

CLI 성공은 TLS 시나리오, 네 구간 분석과 요청한 네트워크·perf 수집의 완료를 요구합니다. 실패한 시도를 삭제하거나 대체하지 않습니다. 정상 TLS 종료 상태는 시나리오 성공과 별도로 남깁니다.

선택적 보고서 도구는 manifest와 C++ 분석 결과만 읽습니다. 원자료 해석과 표본 유효성 판정을 다시 수행하지 않습니다.

```sh
python3 tools/report/report.py out/runs/comparison out/runs/comparison-report
```

중앙값·IQR·기준 중앙값 차이·프로세스 표본의 95% 부트스트랩 구간을 JSON·CSV·Markdown·HTML로 출력합니다. 부트스트랩 기본값은 2,000회와 seed 0입니다. 전체 시도 수·성공 수·지표별 유효 표본 수를 함께 제공합니다.

## 검증

```sh
cmake -S tests -B out/tests/native -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$PWD/.deps/native" \
  -DTURTLE_BINARY_DIR="$PWD/out/build/native" \
  -DTURTLE_TEST_OPENSSL=ON -DTURTLE_TEST_WOLFSSL=ON \
  -DOPENSSL_ROOT_DIR="$PWD/.deps/openssl-3.5.9/install"
cmake --build out/tests/native
ctest --test-dir out/tests/native --output-on-failure
```

실제 netem 시험은 `TURTLE_TEST_NETEM=ON`, perf 시험은 `TURTLE_TEST_PERF=ON`과 `TURTLE_PERF_EXECUTABLE`로 켭니다. 해당 시험에는 권한과 커널 지원이 필요합니다. 필수 시험과 구별하여 실행하고 미수행을 성공으로 세지 않습니다.

[perf](docs/project/perf.md), [독립 실행 검증](docs/project/independence.md), [Wireshark 대조](docs/project/wireshark.md)에 세부 절차가 있습니다. Wireshark는 개발 중 패킷을 확인하는 외부 검증 도구입니다.

측정 구간은 메시지 내부 함수의 비용이 아닙니다. 프레임과 계측은 실행·전송 조건에 영향을 주며, 직접 비용을 빼서 계측 전 성능으로 보정하지 않습니다. 상세 경계와 한계는 [방법론 문서](docs/project/OVERVIEW.md)를 기준으로 합니다.
