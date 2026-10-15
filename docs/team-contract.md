# 병렬 구현에서 공유하는 계약

이 문서는 구현 작업의 연결 지점을 정합니다. 사용자 요구의 우선순위는 `AGENTS.md`와 `docs/implementation-plan.md`를 따릅니다. 헤더를 바꿔야 하면 리더에게 먼저 알립니다.

## 소유권과 실행

- 공개 어댑터 계약은 `include/turtle/adapter.hpp`입니다. 이전 mock 전용 `implementation.hpp` 계약과 시험은 새 계약의 회귀 시험으로 옮긴 뒤 제거했습니다.
- 어댑터는 공유 모듈 하나로 빌드하고 ABI 2 진입점 `extern "C" turtle::ImplementationApi turtle_adapter_v2()`를 내보냅니다. 함수표는 값으로 반환합니다. v1 호환 계층은 없으므로 코어와 모든 어댑터를 같은 공개 헤더로 함께 다시 빌드합니다. 소유 상태를 가진 전역 객체나 싱글톤은 만들지 않습니다.
- 역할 프로세스가 필요한 어댑터 하나를 `dlopen()`으로 불러옵니다. 지휘 프로세스에서는 TLS 라이브러리를 초기화하지 않습니다. 클라이언트와 서버의 모듈은 달라도 됩니다.
- 모듈 파일은 빌드 폴더의 `adapters/<이름>.so`에 둡니다. 실행 인자로 다른 모듈 폴더를 지정할 수 있습니다.
- 컨텍스트와 연결은 각 어댑터의 파생 구조체이며 해당 어댑터의 `close`와 `teardown`으로 파괴합니다. 서비스와 설정은 컨텍스트보다 오래 살아 있어야 합니다.
- 그룹의 공통 이름은 `secp256r1`과 `x25519`, 버전은 `TLS1.3`, 암호 방식은 IANA 이름을 사용합니다. 서명 이름은 가능하면 TLS 이름을 쓰며, 관측하지 못한 값은 빈 문자열과 제한 설명으로 남깁니다.
- 기본 프로필은 서버 인증, P-256 키 교환과 ECDSA P-256 인증서, `TLS_AES_128_GCM_SHA256`, 티켓 0장, 32바이트 핑퐁입니다. 상호 인증은 같은 프로필에서 별도 선택합니다.
- 설정은 `src/config/config.hpp`와 `model::RunConfig`로 전달하며 리더가 구현합니다. 기본 명령은 `turtle run --client openssl --server openssl --profile <파일> --samples 10 --mode timing --output <폴더>`입니다. `--warmups`, `--context`, `--batch`, `--seed`, `--adapter-dir`, `--no-perf`, `--no-kernel-timestamps`, `--no-isolate`, `--no-affinity`를 지원합니다. 도움말과 `capabilities`도 제공합니다.

## 부품 경계

- 모든 부품은 `src/model/model.hpp`의 값 구조를 공유할 수 있습니다. `model.cpp`와 설정 읽기는 리더가 맡습니다.
- worker-2는 `measure/measure.hpp`와 `capability/capability.hpp`의 선언을 구현합니다. `Meter`와 그 힙 추적 상태는 역할 런타임이 소유합니다. 사용할 수 없는 카운터는 `optional`의 빈 값입니다. 교체 가능한 성능 카운터가 불완전하면 기록에 드러냅니다.
- worker-4는 `record/record.hpp`를 먼저 구현해 중간 커밋으로 전달합니다. `Buffer`는 생성 때 저장 공간을 마련하고 `append` 경로에서 추가 할당하지 않습니다. `Writer`는 제한 이전에 파일을 열고 측정 뒤 쓰므로 큰 원자료 때문에 지휘 통로가 막히지 않습니다.
- worker-1은 실행과 통신을 조합합니다. 통신 부품이 계측·기록 부품에 직접 의존하지 않도록 연결 객체나 명시적인 알림 함수를 사용합니다. 새 프로세스, 제한 시간, 비차단 대기, TCP 준비, 응용 데이터 확인, 컨텍스트 입력·출력을 맡습니다.
- worker-3은 세 TLS 어댑터와 `implementations/common/`에 필요한 작은 연결 도우미, `scripts/build-deps.sh`, `scripts/make-pki.sh`, 관련 테스트를 맡습니다. 의존성 빌드 출력은 공유 캐시인 리더 작업 폴더의 `.deps/`를 사용할 수 있습니다. 이 경로를 코드에 하드코딩하지 않고 `TURTLE_DEPS_ROOT` 인자나 환경 변수로 받습니다.
- 각 작업자는 자기 부품의 `CMakeLists.txt`와 `tests/<부품>/CMakeLists.txt`를 쓸 수 있습니다. 리더는 최상위 CMake와 테스트 CMake에서 이를 연결합니다. 필요한 대상과 링크 의존을 메시지로 알려 줍니다.
- 공통 대상 이름은 `turtle_model`, `turtle_config`, `turtle_transport`, `turtle_control`, `turtle_measure`, `turtle_capability`, `turtle_record`, `turtle_lifecycle`, `turtle_interpret`, `turtle_report`입니다. 분석 도구 실행 파일은 `turtle-interpret`, `turtle-report`입니다.
- `third_party/`를 include 경로로 주면 `<nlohmann/json.hpp>`를 사용할 수 있습니다. JSON 처리는 측정 뒤에만 합니다. 코어는 OpenSSL에 링크하지 않으며, 해독 도구와 OpenSSL 어댑터만 필요한 OpenSSL 라이브러리에 링크합니다.

## 원자료 공통 규칙

- 표본 폴더는 `sample-000001/`처럼 만들며, 역할별 `client.jsonl`, `server.jsonl`, `client.keys.log`, `server.keys.log`, `client.context.bin`, `server.context.bin`을 둡니다. 연결별 스트림은 `client.conn-0.sent.bin`, `client.conn-0.received.bin` 같은 이름입니다. 최종 이름을 바꾸려면 worker-1과 리더에게 먼저 알립니다.
- 첫 JSON 줄은 `type: "sample"`이며 `schema`, `sample`, `batch`, `role`, `pid`, `mode`, `valid`, `invalid_reason`, `profile_hash`, `environment_hash`, 전체 설정·환경·지원·선언·보정·연결 결과를 담습니다.
- 사건 줄은 `type: "event"`이며 `schema`, `sample`, `batch`, `role`, `connection`, `sequence`, `kind`, `location`, `call`, `call_id`, `monotonic_ns`, `thread_cpu_ns`, `cycles`, `instructions`, `perf_enabled`, `perf_running`, `heap`, `requested`, `transferred`, `stream_begin`, `stream_end`, `result`, `system_error`를 담습니다. 누락된 계측은 JSON null입니다.
- 이벤트 문자열은 `model::name()`에서 가져옵니다. 방향은 송신 사건의 경우 sent, 수신 사건의 경우 received로 해석합니다. 스트림 위치는 연결별·방향별로 0에서 시작하며 실제 성공한 바이트 수로만 증가합니다.
- 커널 사건은 원래 시각과 식별자, 시계 변환용 짝을 별도로 남깁니다. 경계의 구간 합계에는 커널 사건을 넣지 않습니다. 수신 부가정보가 모든 바이트의 개별 도착 시각이라는 가정도 하지 않습니다.
- 측정 구간은 우선 클라이언트의 첫 Handshake 호출부터 퐁 수신 호출 완료까지, 서버는 첫 성공한 수신부터 퐁 송신 호출 완료까지입니다. 라이브러리 경계의 서버 종료를 기본으로 하며 커널 경계는 별도 관측으로 보고합니다. 각 구간에서 연산·입출력·대기·틈의 합계를 검증합니다.
- 원자료의 선언과 실제 협상·관측 가능 여부를 함께 보존합니다. 무효 표본을 조용히 재시도해 채우지 않습니다.

## 분석과 검증

- 해석은 실제 방향별 TLS 바이트와 NSS 형식 키 로그를 사용하며 최초 필수 암호 방식은 AES-128-GCM/SHA-256입니다. 추가 알고리즘은 지원되는 것을 명시하고 미지원은 분명하게 남깁니다.
- 키 로그가 없거나 바뀐 키 스케줄을 해독할 수 없으면 바이트·구간 보고를 유지하고 해독만 불가로 표시합니다.
- StQ는 정렬된 표본의 가중 구간 평균으로 구현합니다. 로컬 SUPERCOP `stq.h`의 C++ 분기에는 정렬 벡터가 값으로 전달되는 문제가 있으므로 복사하지 않습니다. 표본을 여덟 번 복제해 정렬한 뒤 `[n,3n)`, `[3n,5n)`, `[5n,7n)`을 평균내는 기준과 일치하게 시험합니다.
- 단계별로 부분 완료 커밋과 실행 증거를 리더에게 전달합니다. 다른 작업자가 아직 만들지 않은 부품 때문에 통합이 불가능하면 자기 부품의 단독 시험·구문 검사 결과와 필요한 통합 지점을 함께 보고합니다. 다른 영역을 대신 수정하지 않습니다.
