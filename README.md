# TURTLE — 내 TLS 클라이언트 또는 서버 하나를 측정하기

TURTLE은 Linux에서 TLS 1.3 전체 핸드셰이크와 그 직후의 응용 데이터를 벤치마크한다. **측정할 역할 하나만 지정한다.** 클라이언트를 주면 기본 OpenSSL 서버가, 서버를 주면 기본 OpenSSL 클라이언트가 상대가 된다. 시간과 CPU는 지정한 쪽에서만 재고, 인증과 응용 내용은 양쪽에서 확인한다. 용도가 일반 TLS인지 PQTLS인지에 따라 시나리오를 다시 작성하지 않는다.

## 첫 실행

Linux, CMake 3.20 이상, C/C++20 도구 체인, nlohmann/json 3.12, OpenSSL 3.5 이상 개발 파일과 `openssl` 명령이 필요하다. 기본 실측에는 **대상 스레드에서 접근 가능한 하드웨어 cycles·instructions**가 필요하지만, `perf` 명령이나 libpcap은 필요 없다. 소스 배포물에 외부 라이브러리는 포함하지 않는다. 시스템에 없는 의존성은 [CMake 준비 도구](tools/dependencies.cmake)와 [고정 버전·해시 목록](tools/dependencies.json)을 참고한다.

저장소 루트에서 다음을 실행한다. 먼저 동봉된 연동 앱을 측정 대상으로 써 보면 자기 앱의 통합과 환경 문제를 구분할 수 있다.

~~~sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
./bench.sh --client ./build/turtle-openssl
~~~

기본값은 **S3, mTLS, 예열 1회, 본 측정 2회**다. 일회용 CA가 서버·클라이언트에 서로 다른 인증서를 발급한다. 클라이언트가 `ping`을 쓰고, 서버가 인증과 4바이트 전체를 확인한 뒤 `pong`을 보낸다. 출력 첫 줄의 `Outputs:` 뒤에 새 결과 디렉터리가 나온다. 두 회는 사용법을 확인할 표본이지 성능 분포를 추정할 표본 크기가 아니다. **인자 없는 `./bench.sh`는 TLS 벤치마크가 아닌 소켓 훅 진단**이다.

역할·시나리오를 파일로 남기려면 [단측 S3 명세](examples/one-sided-s3.json)를 사용한다. `target.argv[0]`의 상대 경로는 **명세 파일 위치** 기준이고, 나머지 인자는 셸 해석 없이 그대로 전달한다.

~~~sh
work=$(mktemp -d)
./bench.sh examples/one-sided-s3.json "$work/s3"
./build/turtle analyze "$work/s3"
~~~

`analysis.json`의 `measurement_count`(시행), `successful_measurements`(과업 성공), `eligible_measurements`(유효 표본)를 구분한다. 각 `attempts/*/analysis.json`에는 제외 사유와 지표가 있다. 단조 시계의 시작·끝 사건은 측정 역할의 `endpoint.json`과 `events.jsonl`, 같은 구간의 원누계·TID·활성/실행 시간은 `counters.json`에서 확인한다. 예열·능력 시험·함수 프로파일은 일반 지연 표본이 아니다. 단측 실행의 `scenario_support`는 과업과 필요한 능력을 실제 입증한 `supported`, 서버가 선송신 미지원을 명시한 `unsupported`, 증거가 부족한 `unconfirmed`를 구분한다.

## 내 구현체를 처음 연결할 때

라이브러리나 BIO 포인터만 건넨다고 TURTLE이 핸드셰이크를 진행하거나 CAD/SAD를 쓸 수 있는 것은 아니다. 자신의 역할 앱이 **기존 공개 TLS 호출**을 엔진의 요청에 한 번 연결한다. 이미 연동된 앱이면 이 단계는 필요 없다. [여섯 가지 개발자 제공 항목](DESIGN.md#developer-handoff)과 [공개 C 헤더](include/turtle/role.h)가 계약이다.

1. 앱이 TLS 객체를 만들고 역할별 시험 설정을 적용한다. `TURTLE_CA`, `TURTLE_CERT`, `TURTLE_KEY`, `TURTLE_PEER_NAME`은 로컬 시험 파일 경로와 기대 DNS 이름이다. 쓰지 않는 항목은 빈 값이다. 클라이언트는 서버 체인과 `localhost`를, mTLS 서버는 필수 클라이언트 인증서·체인과 `client.turtle.test`를 검증한다. 인증서 파일을 열었다는 사실만으로 인증 성공을 보고하지 않는다.
2. SDK가 제공하는 비차단 TCP 경로를 BIO 등에 연결하거나, 앱이 소켓을 소유하고 실제 전송 경계에 [카운트 훅](implementations/implementation.h)을 붙인다. **송신 시도 직전**에는 실패할 시도도 세고, **수신 직후**에는 양수 반환만 센다. 상세 관측이나 선송신 증명이 필요하면 실제 처리한 암호문 바이트도 대응시킨다. 훅 호출 수는 레코드 수가 아니다.
3. `turtle_pull`로 엔진이 요청한 동작을 받는다. `turtle_before` → 자기 TLS의 **호출 하나** → `turtle_returned` → 오류 해석 → `turtle_submit` 순서로 진행한다. 부분 성공, 재시도 방향, EOF·오류를 구별하고 핸드셰이크 성공 시 실제 협상·인증 근거를 붙인다. S2/S4의 서버에서만 CF를 기다리지 않는 공개 선송신 경로가 추가로 필요하다. 동작 순서, 재시도 버퍼, 평문 검증, 타임스탬프, PMU는 프레임워크 몫이다.

새 연동에 일괄 `prepare/release/query` 함수표나 시나리오별 러너를 요구하지 않는다. SDK는 TLS 객체를 소유하지 않는다. 예: [OpenSSL 호출 연결](implementations/openssl/implementation.cpp), [wolfSSL 호출 연결](implementations/wolfssl/implementation.cpp). 수정 가능한 `turtle-openssl` 대상 설정과 기본 피어 `turtle-reference` 설정은 별도로 빌드한다.

**기존 빌드 유지:** 소스를 TURTLE 트리로 옮길 필요가 없다. 아래는 설치된 SDK로 독립 OpenSSL 역할 앱을 빌드해 이번에는 서버를 측정하는 예다. 자기 CMake 프로젝트에서는 `find_package(TURTLE CONFIG REQUIRED)`와 `turtle::endpoint`를 사용한다.

~~~sh
cmake --install build --prefix "$PWD/out/sdk"
cmake -S implementations/openssl -B out/my-openssl -DCMAKE_PREFIX_PATH="$PWD/out/sdk"
cmake --build out/my-openssl --target turtle-openssl --parallel 2
./bench.sh --server ./out/my-openssl/turtle-openssl
~~~

단측 프로필은 TURTLE 제어와 계측을 연동한 **실제 역할 앱**을 실행한다. 일반 채팅 앱이나 `openssl s_client` 명령행을 대상 경로에 넣는 것만으로는 계약이 충족되지 않는다. `proc-exec.v1`은 준비 완료 시점과 TLS 작업이 끝난 시점에 실제 역할 프로세스의 실행 파일과 실행 가능한 파일 매핑의 해시를 대조한다. 래퍼 이름만 일치해도 통과한다는 뜻은 아니며, 두 시점 사이에 잠깐 불러와 해제한 모듈까지 증명하지는 않는다. [독립 채팅 예제](mock/README.md)와 구형 `{client:[…],server:[…]}` 실행은 연동 전 동작 확인용이며, 프로세스 종료 성공을 TLS 성능 표본으로 승격하지 않는다.

## 무엇을 어디까지 재는가?

CAD는 클라이언트 요청, SAD는 서버 응용 데이터다. 클라이언트 지연의 시작은 준비된 TCP 연결에서 **자기 첫 핸드셰이크 호출 직전**이다. 각 행은 서버 단독 인증 및 mTLS에 적용한다.

| 시나리오 | 요구하는 순서 | 클라이언트 대표 지연의 끝 |
|---|---|---|
| S0 | 핸드셰이크만 | 자기 핸드셰이크 성공 반환 |
| S1 | 클라이언트가 자기 핸드셰이크 후 CAD, 서버가 전체 검증 | 마지막 CAD 바이트를 수락한 쓰기 반환 |
| S2 | 서버 Finished 뒤 첫 허용 기회에 SAD, CF를 기다리지 않음 | 첫 SAD 평문 읽기 반환 |
| S3 | 서버가 핸드셰이크·인증·CAD 전체 검증 후 응답 | 첫 응답 평문 읽기 반환 |
| S4 | 서버가 먼저 안내, 클라이언트는 안내를 기다리지 않고 CAD, 서버는 인증·CAD 검증 후 응답 | 안내를 제외한 첫 **응답** 평문 읽기 반환 |

전체 내용 검증 완료와 첫 평문 반환은 별개다. S2/S4 지원은 **같은 서버를 사용한 별도 연결**에서 시험한다. 이를 본 측정에서 매번 SAD가 CF보다 먼저 도착했다는 증거로 쓰지 않는다. 상세 계측도 외부 TLS 레코드 헤더만 보고 암호화된 EE·Certificate·CertificateVerify·Finished 각각에 시각을 부여하지 않는다. TCP SEQ/ACK가 입증하는 특정 바이트의 전송·도달과 TLS 평문 반환도 다르다. 서버의 측정 끝점과 상세 판정은 [고정 시나리오](DESIGN.md#scenarios)를 따른다.

## 선택 계측과 다른 Linux 환경

- 기본값은 로컬 루프백이다. 상세 레코드는 `recording: "detailed"`, 필수 캡처는 이에 더해 `required_metrics: ["capture"]`로 요청한다. 요청한 캡처에는 libpcap과 권한이 필요하다.
- 상세 시도의 `analysis.json`에서 `observations.tls_flights`의 `CH`, `SH`, `server_protected_flight`, `client_protected_flight`를 확인한다. 각 항목은 실제 레코드 범위와 로컬 송신 첫 바이트의 호출 진입 또는 수신 마지막 바이트의 호출 반환을 가리킨다. 보호 묶음의 개념적 구성원은 내부 메시지별 시각이 아니다. 경계를 입증하지 못하면 값은 `null`이다.
- 추가 RTT와 손실은 **방향별**로 지정한다. 예를 들어 명세에 `"netem": {"additional_rtt_ms":16,"client_to_server":{"loss_pct":20},"server_to_client":{"loss_pct":0}}`를 넣으면 각 방향에 지연 8 ms를 더하고 **클라이언트→서버에만 손실 20%**를 적용한다. 방향별 `delay_ms`로 비대칭 지연을 지정할 수도 있지만 `additional_rtt_ms`와 함께 쓰지 않는다. 기저 RTT를 포함한 실측 RTT나 유한 표본의 드롭 비율이 정확히 그 값이 된다는 뜻은 아니다. 단측 실행의 `linux-netem.v1`은 `network.json`에 남긴 실행 전후의 실제 qdisc 설정·카운터를 요청 조건과 대조한다. 네임스페이스·망 설정 권한을 얻지 못하면 요청 조건으로 성공을 기록하지 않는다.
- 함수 표본은 `cpu_samples`로 요청하는 별도 시도다. 선택 수집 불가와 필수 요청 실패를 구분한다. CLI 부재나 샘플링 실패가 기본 PMU 원누계 실패와 같은 사유는 아니다. cycles는 가능하나 instructions를 열 수 없는 환경은 `decision_required`로 남긴다. 이를 포괄적인 미지원으로 분류하거나 추정 계수로 채우지 않는다.
- 다른 Linux 호스트에서는 **그 호스트**의 도구 체인·TLS 의존성으로 동일하게 빌드·실행한다. 결과 디렉터리 **전체**를 분석 PC로 복사한 뒤 그 버전의 `turtle analyze`에 복사한 디렉터리 경로를 준다. 재분석은 TLS를 다시 실행하지 않는다. 배포 소스에는 C, C++, 셸, Make/CMake만 사용하며 프레임워크가 커널 권한 설정을 바꾸지 않는다. **실물 ARM64 보드 실행과 보드→PC 재분석은 이번에 검증하지 않았다.**

[검증 결과와 원자료 검산](docs/validation.md) · [설계 기준](DESIGN.md) · [레거시 이관](docs/MIGRATION.md)

앱이 소켓을 소유하고 레코드 계측까지 원한다면 각 실제 `send/recv`를
`turtle_socket_before`와 `turtle_socket_returned`로 감싼다. EINTR 재시도도 별도 호출로 기록하며
두 함수는 errno를 보존한다. 카운트 훅은 별도로 유지한다. 성공한 바이트만 알리는
`turtle_session_wire`는 대안이지만 소켓 호출 시각을 증명하지 않으므로 `records` 필수 표본에 쓸 수 없다.
완전한 양방향 바이트열만 있어도 `observations.record_layout`에는 외부 레코드의 길이와 오프셋이 남는다. 이 값에는 시각이나 암호화된 내부 메시지 식별 결과가 없다.
