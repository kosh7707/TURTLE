# TURTLE — 한쪽에서 재는 TLS 1.3 벤치마크

TURTLE은 **TCP 연결 하나에서 클라이언트 또는 서버 한쪽만 계측**한다. 반대편도 인증과 응용 내용 확인 결과는 제출하지만, 시계·BIO 훅·소켓 이벤트·성능 카운터는 수집하지 않는다. 두 역할은 보통의 TLS 레코드를 주고받는다. 제어 신호는 표준 입출력 파이프에만 흐른다.

## 첫 실행: 직접 발급 mTLS, S3, 캡처·perf 없음

아래 명령은 저장소 루트에서 실행한다. Linux, CMake ≥3.20, C/C++20 도구 체인과 nlohmann/json 3.12가 필요하다. 두 예제 어댑터의 기준 빌드는 x86-64 OpenSSL 3.5.9 및 wolfSSL 5.9.4다. 이미 준비한 설치 경로가 있으면 첫 단계를 생략한다.

~~~sh
# 선택 사항: tools/dependencies.json에 고정된 소스만 내려받고 SHA-256 검증 후 로컬 빌드.
for action in fetch prepare; do
  python3 tools/dependencies.py "$action" all --only json@3.12.0 \
    --only openssl@3.5.9 --only wolfssl@5.9.4 --jobs 4
done
deps="$PWD/.deps/prepared"
ossl="$deps/openssl-3.5.9/install"
wolf="$deps/wolfssl-5.9.4/install"
export LD_LIBRARY_PATH="$ossl/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cmake -S . -B out/build/native -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$deps/json-3.12.0/install" \
  '-DTURTLE_IMPLEMENTATION_DIRS=implementations/openssl;implementations/wolfssl' \
  -DOPENSSL_ROOT_DIR="$ossl" -DWOLFSSL_ROOT_DIR="$wolf"
cmake --build out/build/native --parallel 4

# 별도 말단 키, serverAuth/clientAuth 용도, 같은 테스트 CA가 직접 발급. 기존 디렉터리를 덮어쓰지 않는다.
examples/issue-test-leaves.sh out/certificates "$ossl/bin/openssl"
cli=out/build/native/turtle
"$cli" check examples/mtls-s3.json
"$cli" run examples/mtls-s3.json out/first-s3
"$cli" analyze out/first-s3
python3 tools/report/report.py out/first-s3 out/first-report  # 선택
~~~

기본 실행에 libpcap이나 외부 perf 실행 파일은 필요 없다. `TURTLE_WITH_PCAP`, `TURTLE_WITH_PMU`의 CMake 값은 `AUTO`(기본), `ON`(필요한 인터페이스가 없으면 구성 실패), `OFF`(빌드하지 않음)다.

## 무엇이 한 표본인가?

1. **`check`**는 양쪽 엔드포인트를 각각 오프라인으로 준비·해제하고 암호 설정, 자격 자료, 선택한 계측 기능과 권한을 점검한다. TCP 연결이나 실제 TLS 협상은 하지 않는다.
2. **S2/S4 능력 시험**은 별도 연결이다. 클라이언트가 ClientHello를 쓴 뒤 멈춘다. 서버가 보낸 암호문이 클라이언트 수신 큐에 들어왔는지 확인하고, *서버가 여전히 멈춰 있는 동안* 클라이언트가 안내 평문 전체를 읽어 검증해야 한다. 이 정지는 예열·본 측정에는 없다.
3. **구성별 예열**은 기본 1회다. 최상위 `warmups` 또는 구성별 재정의로 횟수를 미리 정한다(0이면 생략). 예열과 측정은 같은 TLS/응용 경로를 쓰되, **각 시도마다 양쪽 새 프로세스, 새 TCP 연결, 새 TLS 객체와 ID**를 사용한다. 협상·인증·내용·필수 관측 실패는 해당 구성만 막는다.
4. **본 측정**은 `repetitions`개의 블록에서 구성 순서를 시드로 섞어 실행한다. 성공과 별도로 구성 일치 여부, 지표 유효성, 누락 사유를 보존한다. 예열·능력 시험·별도 CPU 프로파일은 성공률, 반복 수, 지연 분포에 들어가지 않는다. 예열 시간이나 계측 비용을 측정값에서 빼지 않는다.

| 시나리오 | 성립 조건 | 클라이언트 지연의 끝 |
|---|---|---|
| S0 | 양쪽 전체 핸드셰이크, 응용 데이터 없음 | 핸드셰이크 성공 반환 |
| S1 | 클라이언트 요청 송신, 서버가 전체 내용 검증 | 마지막 평문 쓰기 성공 반환 |
| S2 | 서버 선송신, 클라이언트가 안내 전체 검증 | 첫 안내 바이트가 포함된 읽기 반환 |
| S3 | 서버가 인증·전체 요청 검증 후 응답, 클라이언트가 전체 응답 검증 | 첫 **응답** 바이트가 포함된 읽기 반환 |
| S4 | 서버 선송신과 인증 후 요청·응답. 클라이언트는 안내를 기다리지 않고 요청을 보냄 | 안내를 제외한 첫 **응답** 바이트의 읽기 반환 |

모든 지연은 **같은 역할의** 첫 TLS 진행 호출 직전부터 잰다. 서버 계측 시 S1은 요청 검증 완료, S2는 선송신 완료, S3/S4는 마지막 응답 쓰기 성공을 구별한다. S2/S4의 선송신 안내는 클라이언트 인증 전에도 노출될 수 있으므로 비밀을 담지 않는다.

## 명세와 원자료

- 각 구성은 고유 `id`, `client/server.binary`와 그대로 전달할 `args`를 가진다. 파일 경로 기준은 **실행 시 작업 디렉터리**다. 입력 파일은 `inputs`에 나열하여 해시를 남긴다. `expected.group/cipher`에 명시한 값은 각 연결에서 실제 조회한 협상 결과와 비교한다.
- `scenario`=`S0..S4`, `auth`=`server|mtls`, `measured_role`=`client|server`. `application.request/greeting/response` 기본값은 각각 `ping/helo/pong`; 비어 있지 않은 UTF-8 문자열, 각 16 KiB 이하. `app_chunk`는 **평문** 호출 상한, `io_chunk`는 **암호문 소켓** 호출 상한이다. 0은 강제 분할하지 않는다.
- `recording`은 `off`(최소 구간 타이머), `basic`(공개 TLS 호출·평문 범위·검증 사건, 기본), `detailed`(공개 훅·소켓·암호문 스트림 추가)다. 셋 다 **동일한 TCP 경로**를 사용한다. OpenSSL의 BIO 전·후 통지와 그 안의 실제 시스템 호출은 다른 사건이다. wolfSSL에서는 공개 송수신 콜백을 기록한다.
- `required_metrics`와 `optional_metrics`: `scenario_wall_ns`(항상 필수), `records`, `public_io`, `headers`, `capture`, `perf_counters`, `cpu_samples`. 레코드·BIO·패킷 대조는 `detailed`를 지정한다. 미지원 훅, 불완전한 스트림, 캡처 드롭, 권한 거부는 **0이 아니다**. 권한이 필요한 관측을 필수로 선언했으면 조용히 다른 측정으로 대체하지 않는다.
- `network`는 `loopback`(기본) 또는 `netem`이다. 캡처 요청 시 실제 리슨 포트로 필터링하여 측정 역할의 인터페이스에서 SYN 전에 준비한다. [netem 예제](examples/compare.json). TLS 평문 처리나 첫 전송의 도달 순서를 임의의 재전송 사본 ACK로 입증하지 않는다.
- [하드웨어 카운터](examples/perf-counters.json)는 대상 스레드의 사용자 공간 cycles/instructions와 enabled/running 시간을 남긴다. [함수 표본](examples/perf-sampling.json)은 **구성별 별도 프로파일 시도**에서 `perf record`로 수집하고 `perf script`로 복원한다. 카운터를 켠 연결의 시간도 일반 지연 표본에 섞지 않는다.
- **`manifest.json`**: 확정 명세·실행 순서·목적·ID·진단 실패/차단 사유·회수 파일 해시. **`attempts/NNNNN/`**: 두 역할의 `endpoint.json`, 제어 로그, 요청한 원자료와 `analysis.json`. 시작/끝 사건은 측정 역할의 `endpoint.json → scenario.begin_event/end_event`를 `events.jsonl`의 ID에 연결하여 검산한다. 상세 기록에서는 방향별 레코드가 실제 소켓·공개 I/O 바이트 구간을 참조한다. Finished 경계는 **해당 연결**의 외부 헤더·AEAD·양쪽 어댑터가 선언한 무패딩 등 조건·응용 평문 총량이 맞을 때만 판정한다.
- **루트 `analysis.json`**은 본 측정과 진단 목록을 분리한다. 원자료가 없어지거나 선행 시험이 더 이상 성립하지 않으면 `analyze`는 해당 표본을 채택하지 않는다. v2 매니페스트의 이전 TU 프레임 형식은 이전 분석 경로에서만 읽는다.
- 실패한 **본 측정**을 다시 시도하려면 `turtle retry OLD_RUN FAILED_RUN_ID NEW_OUTPUT`을 쓴다. 기존 결과는 읽기만 하고 새 배치에서 사전 점검·필요한 진단을 다시 거친다. 새 측정은 `retry_of`로 원래 ID를 가리키며 기존 분모를 변경하지 않는다.

### 상세 계측 분석 코드를 읽는 순서

1. [BIO·소켓·헤더 관측](src/analysis/observations.cpp) — 한 연결의 방향별 바이트 범위를 로컬 호출에 연결한다. BIO나 헤더 통지가 빠져도 검증된 소켓 기록은 남긴다.
2. [TLS 레코드의 의미](src/analysis/record_semantics.cpp) — 같은 연결에서 양방향 Finished가 끝난 레코드를 판정하고, 이후의 평문 범위를 요청·선송신 안내·응답으로 구분한다. 전제가 맞지 않으면 경계를 추측하지 않는다.
3. [TCP 전송 근거](src/analysis/tcp_evidence.cpp) — 캡처가 있을 때만 반복 바이트를 세고, 특정 패킷 사본의 ACK와 앞 단계에서 식별한 레코드를 대조한다. 다른 패킷의 ACK나 평문을 읽은 시각으로 그 사본의 선후를 대신 판정하지 않는다.

## 외부 어댑터와 재현 시험

[공개 C 계약](include/turtle/implementation.h)에는 준비·해제, 핸드셰이크 진행, 평문 읽기/쓰기, 살아 있는 연결의 최종 협상·인증 조회가 있다. 버퍼는 빌려 쓰며 부분 성공만 위치를 옮긴다. WANT_READ/WANT_WRITE이면 같은 버퍼와 길이로 재시도한다. 선송신과 상세 훅은 선택 사항이다. 예열용 진입점이나 OpenSSL 타입은 없다. `main`에서 함수표를 [turtle_endpoint_main](include/turtle/endpoint.h)에 넘긴다.

~~~sh
cmake --install out/build/native --prefix "$PWD/out/sdk"
# 아래 소스 디렉터리 대신 저장소 밖으로 복사한 어댑터 디렉터리도 가능하다.
cmake -S implementations/openssl -B out/external-openssl \
  -DCMAKE_PREFIX_PATH="$PWD/out/sdk" -DOPENSSL_ROOT_DIR="$ossl"
cmake --build out/external-openssl
cmake -S implementations/wolfssl -B out/external-wolfssl \
  -DCMAKE_PREFIX_PATH="$PWD/out/sdk" -DWOLFSSL_ROOT_DIR="$wolf"
cmake --build out/external-wolfssl
~~~

어댑터 라이브러리에는 `turtle::contract`와 해당 TLS 라이브러리만, 엔드포인트 실행 파일에는 `turtle::endpoint`와 어댑터를 링크한다. 런타임은 C++이므로 C 어댑터도 최종 링크 프로젝트에서 C와 C++ 언어를 활성화한다.

~~~sh
cmake -S tests -B out/tests -DCMAKE_PREFIX_PATH="$deps/json-3.12.0/install" \
  -DTURTLE_BINARY_DIR="$PWD/out/build/native" -DOPENSSL_ROOT_DIR="$ossl" \
  -DTURTLE_TEST_OPENSSL=ON -DTURTLE_TEST_WOLFSSL=ON
cmake --build out/tests --parallel 4
ctest --test-dir out/tests --output-on-failure -j4
~~~

`TURTLE_TEST_NETEM=ON`은 네임스페이스·veth·qdisc 및 PCAP 권한이 필요하다. `TURTLE_TEST_PERF=ON`은 접근 가능한 PMU와 stock perf가 필요하다(`TURTLE_PERF_EXECUTABLE`로 지정 가능). `recording_cost`는 같은 구성에서 기록 끔·기본·상세의 별도 연결을 비교한다. [독립 strace 검산](tools/verify_socket_trace.py)과 [TShark 검산](tools/wireshark/check_lifecycle_capture.py)은 선택 시험이다. 외부 추적을 켠 실행의 지연은 성능 비교에 쓰지 않는다. **[실행으로 확인한 결과와 증거 위치](docs/validation.md)**
