# 내 TLS 구현 연결하기

아직 실행하지 않았다면 [첫 실행](../README.md#첫-실행)부터 시작하세요. 직접 포팅할 때는 `implementations/`에 TLS 원본을 두고 [두 시작 파일](../implementations/README.md)을 편집합니다. TURTLE이 같은 브리지로 client/server를 각각 링크하므로 벤더 등록이나 별도 서버 프로그램은 필요 없습니다.

## 빌드 레시피

TURTLE은 `implementations/`를 작업 디렉터리로 하여 `./build.sh WORK PREFIX [native 인자…]`를 실행합니다. `WORK`와 `PREFIX`는 새 빌드마다 제공하는 서로 다른 빈 절대 경로입니다. 원본을 직접 고치지 말고 `WORK`에서 빌드하세요. 소스 트리 안에서만 빌드할 수 있다면 `WORK`에 복사해서 빌드합니다. `shift 2` 뒤의 `"$@"`는 `./bench.sh --` 뒤의 원래 인자이므로 원소별로 그대로 전달하세요.

`PREFIX`에 해당 구성으로 빌드한 SDK를 설치합니다.

- 공개 헤더 및 같은 빌드에서 생성한 구성 헤더.
- ELF 공유 라이브러리(SONAME 포함). `-l이름`을 쓰면 링커가 찾는 `lib이름.so`도 설치합니다.
- SDK의 헤더·라이브러리를 가리키는 pkg-config `.pc` 파일. 기존 파일이 올바르면 그대로 사용하세요. 없다면 레시피에서 소비 정보를 만들어 설치할 수 있습니다. 모듈명과 소스 폴더명이 같을 필요는 없습니다.

현재 소비기가 받는 공개 컴파일 플래그는 `-I경로`, `-D정의`, `-U정의`, `-pthread`입니다. `.pc`에는 실제로 읽는 사설 헤더 경로와 사설 링크 입력(`-L경로 -l이름` 또는 공유 파일 절대 경로)이 있어야 합니다. 정적 라이브러리만 제공하거나 CMake 대상만 내보내는 SDK, 다른 ABI로 교차 빌드하는 제출은 지원하지 않습니다. 작업 및 빌드 경로에 `;`, `:`, 줄바꿈을 쓰지 마세요. 빌드는 샌드박스가 아니므로 신뢰하는 레시피와 소스만 사용하세요.

| 진행 상태 | 다음에 할 일 |
|---|---|
| `./bench.sh --build-only --out JOB` 성공 | `JOB/build/bin/{client,server}`가 생깁니다. 두 `.map`과 `link-evidence.txt`로 링크 입력을 확인할 수 있습니다. 아직 TLS 연결은 하지 않았습니다. |
| 원본 빌드 실패 | `JOB/build/native.log`와 `native.exit`를 보세요. 원본·인자·레시피를 고친 뒤 새 `JOB`에서 빌드합니다. |
| 유효한 링크 후보가 여러 개이거나 결정할 수 없음 | `JOB/build/link.*/candidates.tsv`와 같은 폴더의 링크 로그를 보세요. TURTLE은 사설 SDK를 시스템 동명 라이브러리로 대체하거나 다른 모듈을 추측해 선택하지 않습니다. |
| 설치한 후보 중 하나를 명시적으로 지정 | `./bench.sh --build-only --resume JOB --use MODULE`에 처음 사용한 native 인자(`-- …`)를 그대로 붙이세요. `MODULE`은 사설 pkg-config 모듈명입니다. 레시피나 입력을 바꿨다면 새 빌드로 시작하세요. |

## 포팅

[공개 헤더](../src/include/turtle/implementation.hpp)의 일곱 함수를 구현합니다. TURTLE이 소켓과 역할 실행, 일반 앱 송수신 반복, 데이터 검증을 담당합니다. 브리지는 빌려 쓰는 각 연결의 TLS 상태, 인증, 암호문 관측을 담당합니다. [OpenSSL 코드](examples/submissions/openssl/implementation.cpp)에서 구현 순서를 볼 수 있습니다.

| 함수 | 지켜야 하는 동작 |
|---|---|
| `turtle_tls_setup` / `turtle_tls_free` | 주어진 역할·CA·피어 이름·인증서와 키로 새 TLS 1.3 세션을 만들고 정리합니다. 재개와 클라이언트 0-RTT는 사용하지 않습니다. setup 실패는 null이며 빌린 fd는 닫지 않습니다. |
| `turtle_tls_set_hooks` | 실제 암호문 전송·수신 경로에 훅을 설치하고 null이면 해제합니다. 상대역에는 이 훅을 설치하지 않습니다. |
| `turtle_tls_connect` / `turtle_tls_accept` | 로컬 핸드셰이크 및 인증을 완료해야 `TURTLE_TLS_OK`를 반환합니다. 클라이언트의 일반 읽기도 S2에서 핸드셰이크를 진행할 수 있어야 합니다. 서버에 인사가 있으면 Server Finished 뒤, Client Finished를 기다리기 **전**에 전량을 쓰고 그 후 핸드셰이크를 마칩니다. 지원하지 않으면 `TURTLE_TLS_UNSUPPORTED`를 반환하세요. |
| `turtle_app_send` / `turtle_app_recv` | 재시도 처리는 브리지에서 합니다. 짧은 읽기·쓰기는 허용됩니다. 실제 양수 길이, 읽기의 EOF는 0, 오류는 음수를 반환하세요. |

[관측 API](../src/include/turtle/observe.h)로 TLS 결과에서 확인한 세션 정보(버전·suite·그룹·피어 이름), `resumed`, `early_data`, `verify_peer`, `peer_cert_present`, `peer_verified`, `auth_accepted`를 보고하세요. 내부에서 보내는 서버 인사는 `write_attempt`와 실제 수락 길이의 `write_accepted`를 별도로 남깁니다. 일반 앱 송수신의 기록은 실행기가 남깁니다.

암호문 훅은 같은 연결 스레드에서 `coverage`와 `transfer_begin`/`transfer_end` 한 묶음을 사용하세요. 설치 후 TLS 전에 coverage를 열고, 모든 호출을 실제 반환값과 짝지어 기록하고, 해제할 때 닫습니다. 짝짓지 못하면 `active=-1`로 표시합니다. 과거의 `before_send`/`after_recv`만 사용할 수도 있으나 송신 요청은 완료된 송신이 아니므로 성능 검증에 필요한 전송 증거를 충족하지 않습니다. 두 훅 방식을 동시에 쓰지 마세요.

관측기는 측정 중 제한된 메모리(프로세스당 기록 8192개, 복사하는 데이터 4 MiB)를 쓰며 일반 이벤트는 측정 중 직렬화하거나 pipe에 쓰지 않습니다. 정상 종료 때 증거를 마감합니다. 장기 실행 앱이나 `_exit()` 호출 전에는 모든 관측을 끝내고, 측정 구간 밖에서 동시 콜백 없이 `turtle_observe_flush()`를 호출하세요. 증거가 누락되거나 기록이 넘치면 유효한 관측으로 간주하지 않습니다.

## 실행

- `./bench.sh --run-from JOB --out NEW_RUN`은 이미 링크한 빌드를 다시 실행합니다. 기존 빌드를 이동·수정하지 말고, 없는 결과 디렉터리를 지정하세요. 현재 `implementations/` 입력과 native 레시피는 재사용에서 읽지 않습니다. 빌드와 함께 실행하려면 `./bench.sh`에 실행 옵션을 바로 붙일 수 있습니다.
- `--scenario all --role both --auth both`는 S0–S4 × 계측 역할 × 인증 방식의 20가지입니다. `both` 역할은 한 연결의 양쪽이 아니라 **역할마다 별도의 연결**입니다. 조합마다 doctor 한 번으로 실제 실행을 확인한 뒤 예열과 본 시도를 실행합니다. 매 시도는 새 프로세스·새 연결입니다.
- `--tcp-nodelay on|off`는 양쪽 소켓에 적용하며 기본은 `on`입니다. 실험 간 비교에서는 이 값을 고정하세요. `--credentials DIR`에는 `ca.crt`, `server.crt`, `server.key`와 mTLS일 때 `client.crt`, `client.key`를 두세요. 피어 이름은 `localhost` / `client.turtle.test`입니다. 지정하지 않으면 `openssl` 명령으로 시험용 인증서를 발급합니다.
- 그룹·cipher suite는 TLS 브리지에서 설정합니다. 기존 앱, 맞춤 페이로드, 네트워크 프로필을 쓰려면 [SDK 가이드](sdk-guide.ko.md)를 보세요.

## 시나리오와 측정 구간

측정은 지정한 역할의 첫 TLS 호출 직전부터 시작하며 TCP 연결 수립은 제외합니다. 아래는 해당 역할의 로컬 종료점이지 패킷 전송·도착 시각이 아닙니다.

| 시나리오 | 교환 | 클라이언트 종료점 | 서버 종료점 |
|---|---|---|---|
| S0 | 핸드셰이크만 | 핸드셰이크 완료 | 핸드셰이크 완료 |
| S1 | 클라이언트 요청, 응답 없음 | 요청 전량 쓰기 수락 | 요청 전량 검증 |
| S2 | 서버 선송신 인사만 | 인사 전량을 받은 읽기 반환 | Client Finished 수신이 목표이나 현재 구분할 수 없어 기본 시간·사이클은 비움 |
| S3 | 요청과 응답 | 응답을 처음 읽은 반환 | 응답 전량 쓰기 수락 |
| S4 | 서버 선송신 인사, 요청과 응답 | 인사가 아닌 응답을 처음 읽은 반환 | 응답 전량 쓰기 수락 |

S3/S4의 서버는 핸드셰이크와 요청 전량 검증 뒤에만 응답합니다. S4에서 클라이언트는 자기 핸드셰이크를 완료하고 요청을 모두 보낸 뒤 인사와 응답을 읽습니다. S2의 첫 인사 읽기와 서버 인사 쓰기 수락은 각각 별도 보조값입니다. 서버가 인사를 썼다고 해서 클라이언트가 자신의 Finished 전송 전에 인사를 받았다는 뜻은 아닙니다.

## 결과

- `cases.csv`: 조합별 `passed`, `unsupported`, `failed`, `insufficient_evidence`와 요청·검증된 본 시도 수. 조합이 통과하지 않으면 실행은 0이 아닌 코드로 끝납니다.
- `results.csv`: 확인 가능한 연결별 행. `task_success`와 `evidence_state`는 앱/TLS 작업과 증거의 판정을 나눕니다. `wall_ns`/`wall_status`는 실제 경과 시간, `cycles`/`pmu_status`는 계측 스레드의 CPU 사이클 및 가용 상태입니다. `performance_qualified`와 `qualification_reason`은 별개이므로 PMU가 없다는 이유로 유효한 시간까지 버리지 마세요.
- `client_stderr`·`server_stderr`는 새 결과 폴더 기준 상대 경로입니다. 더 확인하려면 결과의 `runs/` 아래에서 `connection_id`로 양쪽 앱 입출력, 역할 지도와 대상 역할의 훅 CSV를 대조하세요. 누락·불일치한 연결은 결과 행 자체가 없을 수 있습니다. 기본 경로는 CSV를 사용하며, JSON/NDJSON은 상세 진단·재분석용입니다.
