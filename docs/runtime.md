# 엔드포인트 실행과 통신

## 소유권과 실행 순서

`src/main.cpp`는 설정을 읽고 실행 또는 지원 여부 표시로 분기합니다. `lifecycle::run`은 지휘 프로세스에서 표본 폴더를 만들고, 매 표본마다 서버와 클라이언트를 각각 새 프로세스로 만듭니다. 지휘 프로세스에서는 TLS 모듈을 불러오거나 라이브러리를 초기화하지 않습니다.

역할 프로세스는 기록 파일, 고정 크기 기록 버퍼, 계측기, 어댑터 모듈, 서비스, 컨텍스트를 이 순서로 준비합니다. 설정과 서비스는 컨텍스트보다 오래 살고, 연결은 컨텍스트보다 먼저 해제합니다. 모듈을 내리기 전에 컨텍스트와 연결을 어댑터 함수로 파괴합니다. `Meter`와 모든 TLS 호출은 같은 역할 스레드에서 실행합니다.

`dlopen`과 동적 로더의 작업은 `SETUP_BEGIN`보다 앞입니다. 따라서 별도로 남기는 셋업 구간도 어댑터의 `setup()` 호출 비용이며, 프로그램·모듈 로딩 전체의 비용이라고 부르지 않습니다.

표본 안에서는 한 번 셋업한 컨텍스트로 `warmups + connections`개 연결을 차례로 실행합니다. `--connections N` 또는 프로필의 `measurement.connections`는 준비 연결 뒤에 측정할 연결 수이며 기본값은 1입니다. 앞의 준비 연결은 분포에서 제외하고, 뒤의 측정 연결은 순서별로 따로 보고합니다. 같은 프로세스 안의 여러 연결을 서로 독립인 표본처럼 합치지 않습니다. 준비·측정 연결의 합은 1~1,025개입니다. 모든 TCP 소켓과 대기 객체, 출력 파일은 제한 전에 만듭니다. 각 연결의 TCP 준비 상태를 확인한 뒤 별도 Unix 소켓 통로에서 준비 신호를 교환합니다. TLS 연결 열기 이후에도 양쪽이 준비 신호를 교환한 뒤 핸드셰이크를 시작합니다. 측정 TCP에는 제어 신호를 보내지 않습니다.

`control::Waiter`는 생성 때 `epoll` 파일을 만들고 소켓을 등록합니다. 자원 제한 뒤에는 기존 파일에 대한 관심 사건 변경과 대기만 합니다. Linux의 `poll`은 `RLIMIT_NOFILE=0`일 때 파일 수 인자 때문에 실패하므로 사용하지 않습니다. `RLIMIT_NOFILE`과 `RLIMIT_NPROC`의 0 제한은 프로세스의 실행 조건이며 보안 격리 장치라는 뜻은 아닙니다.

지휘 프로세스는 역할 프로세스를 만든 뒤에만 자기 CPU를 고정합니다. 다음 표본을 만들기 전에 원래 허용 CPU 집합을 복원하므로 자식이 지휘 프로세스의 한 코어 제한을 물려받지 않습니다. 역할 프로세스는 자기 CPU를 별도로 고정합니다.

조회 시나리오에서는 표본마다 TLS 서버, TLS 클라이언트, 모의 CA 세 자식을 소유합니다. 클라이언트의 조회 TCP와 TLS TCP는 서로 다른 준비 연결이며, 모의 CA는 TLS `Role`에 포함되지 않습니다. 기준 PEM 객체는 지휘 프로세스가 실행 시작 때 한 번 읽어 불변 snapshot으로 보유합니다. 클라이언트는 연결마다 캐시를 같은 empty/fixed snapshot으로 직접 복원한 뒤 조회하고, `USABLE_OBJECT`가 된 뒤에만 TLS를 시작합니다. 이 객체는 stock TLS 인증서 입력을 대체하지 않습니다.

`lookup.enabled=false`이면 조회 객체나 CA 입력을 요구하지 않고 TLS 서버와 클라이언트 두 자식만 만듭니다. attempt 원장 참여자와 필수 결과 파일도 이 두 역할뿐이며 CA·lookup 결과를 빈 파일이나 가짜 성공으로 만들지 않습니다. `lookup.enabled=true`의 기존 세 자식 계약은 그대로 유지합니다.

클라이언트의 TLS `Meter`, 조회 heap tracker, 모의 CA의 `Meter`와 heap tracker는 소유권을 나눕니다. 조회 사건의 시계·perf는 클라이언트 TLS `Meter`를 한 번 읽고 heap 필드만 조회 도메인 값으로 바꿉니다. 조회용 perf 그룹을 따로 열지 않습니다. 모의 CA process·입출력·대기·heap은 CA 프로세스의 원자료에 독립적으로 남깁니다.

TCP 준비에서는 `ESTABLISHED`와 읽지 않은 바이트 0뿐 아니라 설정 후 조회한 비차단 플래그·`TCP_NODELAY`·송수신 버퍼·수신 시각 옵션도 확인합니다. 실제 버퍼 크기를 요청값과 혼동하지 않고 각 연결의 원자료에 남깁니다. 격리 시험은 제한값 조회에 더해 실제 새 `socket()` 호출이 `EMFILE`로 실패하는지도 확인합니다.

컨텍스트 입력 폴더를 지정하면 지휘 프로세스가 역할별 파일을 첫 자식 생성 전에 한 번만 읽습니다. 매 표본의 셋업은 이 고정 입력을 받으며, 앞 표본의 출력으로 초기 상태를 누적 갱신하지 않습니다. 입력 파일은 다시 실행할 때 필요하므로 결과와 함께 보존해야 합니다. 역할 원자료에는 실제 입력 크기와 지문을 남깁니다.

## 비차단 호출과 관측

`transport::Channel`은 빌린 소켓과 비소유 관측 콜백만 가집니다. 계측기나 기록 부품에는 의존하지 않습니다. 실제 송수신 전후에 호출하는 관측 콜백은 런타임이 소유하며, 성공한 바이트만 방향별 스트림과 누적 위치에 넣습니다. 수신은 `recvmsg`로 수행하고, 사용 가능한 소프트웨어 커널 시각은 원래 실시간 시계 값으로 따로 기록합니다. 이 값이 모든 바이트의 개별 도착 시각이라는 뜻은 아닙니다. 송신 커널 시각과 하드웨어 시각은 구현하지 않았습니다.

`WantRead`나 `WantWrite`를 반환한 호출은 같은 작업과 같은 버퍼로 다시 실행합니다. 성공한 부분 바이트만 응용 버퍼의 위치를 이동합니다. 서버는 정해진 핑을 확인한 뒤 퐁을 보내고, 클라이언트는 퐁을 확인합니다. 실제 TLS 어댑터에서는 TLS 1.3, 전체 핸드셰이크, 인증서 검증 성공을 확인합니다. `mock`은 암호화도 인증서 검증도 하지 않으며 선언과 미완료 설명에 그 차이를 남깁니다.

클라이언트 구간은 첫 핸드셰이크 호출부터 마지막 퐁 수신 호출 완료까지입니다. 서버 구간은 첫 성공한 수신 반환부터 마지막 퐁 송신 호출 완료까지입니다. 호출 완료 사건의 `result`는 `Step` 값이며, 응용 호출에는 `AppResult.step`을 기록합니다. `Done`은 2입니다. 네이티브 소켓 비교에서는 프레임워크 송수신이 보이지 않으므로 `library-only`로 표시하고 바이트와 커널 관측이 없음을 남깁니다.

### callback과 native 경로의 관측 가능성

OpenSSL 어댑터는 `framework_io=true`인 callback 경로와 `false`인 native socket 경로를 지원합니다. wolfSSL과 Mbed TLS는 native 경로를 지원하지 않으며 설정을 거절합니다. native 지원을 추정하거나 이 두 어댑터에 가짜 결과를 만들지 않습니다.

callback 경로에서는 `transport::Channel`을 지난 TLS stream 바이트와 I/O 사건을 기록합니다. 수신 시각 설정이 실제로 준비됐으면 kernel receive 사건을 수집할 통로도 available입니다. 그러나 `availability.kernel_receive_events.available=true`는 **수집 경로가 설정·지원됐다는 뜻**이지 특정 실행에서 kernel timestamp 사건이 실제로 하나 이상 생겼다는 증거가 아닙니다. 실제 `raw_timestamp_ns`가 있는 원자료 사건을 확인해야 발생을 주장할 수 있습니다.

native 경로의 TLS 라이브러리는 소켓을 직접 사용하므로 framework TLS stream, I/O 사건과 kernel receive 사건을 볼 수 없습니다. 세 항목을 0으로 쓰지 않고 `available=false`, `reason=native_socket_io_not_observed`로 기록합니다. 네이티브 클라이언트는 첫 handshake 호출부터 마지막 app receive 호출까지의 호출 경계가 남으므로 경과 시간과 스레드 CPU 차이는 보고할 수 있습니다. 다만 computation/I/O/wait/gap 분해와 stream byte metric은 `null`입니다. 네이티브 서버는 주 구간 시작인 첫 성공 framework receive를 볼 수 없으므로 `start_sequence=null`, `primary_window.available=false`, 이유 `server_first_receive_not_observed`로 남기며 경과·CPU를 만들지 않습니다.

TLS 인증과 32바이트 핑퐁이 성공한 기능 유효성과 특정 metric의 관측 가능성은 별도 상태입니다. native 서버의 주 구간이 없어도 기능 결과는 유효할 수 있고, 반대로 metric이 존재해도 application 검증이나 attempt/network integrity 실패를 성공으로 바꾸지 않습니다.

셋업 시작과 끝의 스냅샷은 실제 호출 경계에서 얻고, 어댑터의 할당 함수 지원 선언을 확인한 후 기록합니다. 지원되지 않는 힙 관측은 0이 아니라 빈 값입니다. 누락되거나 다중화된 성능 카운터는 `perf_complete=false`입니다.

## 저장과 무효 표본

선택한 컨텍스트 입력 폴더의 `client.context.bin` 또는 `server.context.bin`을 셋업 전에 읽습니다. 셋업에 전달한 바이트 수와 저장한 바이트 수, 직렬화 지원 선언을 기록합니다. 역할별 컨텍스트 출력은 미리 열린 파일에 씁니다. 저장된 상태의 의미는 어댑터 선언에 따르며, 세션 재개를 허용한다는 뜻이 아닙니다.

역할 프로세스는 처리할 수 있는 실행 오류를 `valid=false`와 이유로 기록합니다. 지휘 프로세스는 전체 표본에 제한 시간을 두고 자식을 회수합니다. 자식이 종료되거나 시간 초과로 기록을 끝내지 못하면 역할 파일이 비어 있을 수 있습니다. 이 경우에도 `director.txt`에 무효 상태를 남깁니다. 무효 표본은 다시 채우지 않고 실행을 끝냅니다. 기존 표본 폴더를 덮어쓰지 않습니다.

### attempt deadline과 bounded cleanup

조회 실행의 `timeout_ms`는 setup, listener, TCP 준비, phase acknowledgement, 조회, TLS와 정상 flush 전에 공유하는 하나의 absolute steady-clock deadline입니다. 단계가 바뀔 때 시간을 새로 주지 않습니다. 최초 terminal 원인을 다음 규칙으로 고정합니다.

- deadline을 먼저 넘기면 `timeout`입니다.
- deadline 전에 실행 오류를 먼저 확인하면 `error`이며, 뒤의 flush 중 deadline이 지나도 timeout으로 덮지 않습니다.
- 실행은 끝났지만 필수 기록만 완전하지 않으면 `incomplete`입니다.
- 뒤따른 flush 오류, kill과 누락은 `secondary_reasons`와 artifact 상태로 남깁니다.

abort를 처음 감지한 시각에 `abort_time + flush_grace_ms`를 한 번 계산합니다. 기본값은 500ms이고 허용 범위는 1~5,000ms입니다. 이 유예 동안 새 연결·조회·TLS 측정을 시작하지 않고 가능한 partial 기록과 최종 소켓 관측만 flush합니다. 유예를 재시작하거나 정리 오류 때문에 연장하지 않습니다. 유예가 끝나면 소유 자식에 SIGKILL을 보내며, 운영체제 wait/reap에는 별도의 고정 250ms 복구 상한을 둡니다. 모든 소유 자식 회수를 증명하지 못하면 다음 attempt를 시작하지 않고 fatal로 남깁니다.

`samples`는 attempt 분모입니다. `fail-fast`는 첫 실패 뒤 남은 attempt를 `not_attempted`로 기록합니다. `fixed-attempts`도 회수를 확인한 attempt 오류 뒤에만 계속하며, 치명적인 환경·셋업 실패는 남은 수를 `not_attempted`로 끝냅니다. 원장은 `requested = started + not_attempted`와 `started = success + timeout + error + incomplete`를 지켜야 합니다.

### 전달받은 네트워크 namespace

`scripts/netem-study.py`는 host 밖이 아니라 새 user/network namespace 안에서 data namespace와 링크를 소유합니다. `lookup.enabled=true`이면 client/server/ca/router 네 namespace·네 veth 링크를 만들고 C++는 client/server/ca FD를 빌립니다. `lookup.enabled=false`이면 client/server/router 세 namespace·두 veth 링크만 만들고 C++는 client/server FD만 빌립니다. 각 자식은 `setns`한 뒤 listener와 socket을 만듭니다. router FD와 생성·삭제 권한은 C++에 전달하지 않습니다. host route·interface·qdisc와 `/run/netns`도 바꾸지 않습니다.

namespace helper를 만든 parent는 고정 시간만 기다리지 않습니다. helper가 `unshare`와 자기 namespace 진입을 마친 뒤 전용 readiness pipe에 신호를 쓴 다음에만 parent가 `/proc/<pid>/ns/net` FD를 엽니다. 신호에는 유한 timeout을 두며, EOF·timeout·자식 조기 종료는 setup 실패입니다. 이는 빠른 동시 실행에서 아직 이전 namespace인 PID의 FD를 여는 시작 race를 막기 위한 제어 통로입니다.

Python과 지휘 프로세스는 setup/scenario/cleanup begin/end를 JSON 한 줄로 교환합니다. 각 ack의 `<attempt>:<phase>:<edge>` observation ID가 원장과 network observation을 연결합니다. attempt마다 qdisc를 삭제·재생성하므로 이전 큐와 카운터를 다음 attempt의 결과로 넘기지 않습니다. runner의 observer/helper 정리 500ms와 C++ 자식 flush grace 및 250ms OS reap 상한은 서로 다른 소유 자원에 적용합니다.

고정 timeout 검증에서는 세 attempt가 모두 timeout으로 남았고, 각 attempt의 missing artifact와 partial phase window도 보존됐습니다. 세 attempt 모두 cleanup grace 뒤 살아 있던 소유 자식에 실제 SIGKILL을 보내고 reap했습니다. 250ms는 SIGKILL 뒤 운영체제 회수를 기다리는 최대 상한이지 측정된 정리 시간이 아닙니다. N05 loss 64 attempts에서는 이 강제 종료 경로가 필요하지 않았습니다. 합성 EIO 때문에 회수 완료를 증명할 수 없는 분기와 소유 PID 제한은 테스트 전용 시스템 호출 wrapper로 확인합니다. 프로덕션 오류 주입 옵션은 추가하지 않았습니다.

## 검증과 빌드 연결

리더의 최상위 빌드는 `src/control`, `src/transport`, `src/lifecycle`, `implementations/mock`를 연결합니다. 테스트 프로젝트에는 `tests/control`, `tests/transport`, `tests/lifecycle`를 연결합니다. 이전 정적 mock 전용 시험은 새 모듈 시험으로 대체했습니다.

- `turtle_control_test`: 별도 프로세스 사이의 준비 장벽을 확인합니다.
- `turtle_transport_test`: 실제 loopback TCP, 준비 상태, 비차단 읽기, 실제 성공 바이트와 관측 횟수를 확인합니다.
- `turtle_lifecycle_test <모듈 폴더>`: 새 프로세스 4개, 표본마다 준비 연결과 측정 연결, 셋업의 제한 이전 실행, 연결 열기의 제한 이후 실행, TLS 이전의 빈 TCP, 검증 실패 후 다음 표본 중단을 확인합니다. 모의 실행이며 실제 TLS 성공 증거로 쓰지 않습니다.
- `turtle_runtime_tls_test <모듈 폴더> <인증서 폴더> [클라이언트 모듈] [서버 모듈]`: 서버 인증과 상호 인증을 시간·메모리 모드에서 각각 두 표본과 준비 연결로 실행합니다. 실제 TLS 1.3 결과와 응용 데이터 확인을 검사합니다. 인증서는 `scripts/make-pki.sh`로 별도 준비합니다.
- `pure_tls_netem.py`: 조회가 꺼진 OpenSSL TLS를 0ms·20ms 양방향 netem 조건에서 각 2 attempts 실행하도록 구성되어 있습니다. 세 namespace·두 링크·두 qdisc, CA/lookup 결과 부재, TLS 해독, 소유 자원 정리, 역할별 경과·스레드 CPU가 든 네 보고 그룹을 검사합니다.
- `io_path.py normal`: OpenSSL callback/native와 서버 인증/상호 인증 네 조건에서 실제 TLS·응용 교환, 역할별 availability와 offline 해석·보고를 검사합니다.
- `io_path.py external`: 기존 lookup=false zero-loss runner를 callback/native 각각 2 attempts에 재사용합니다. router receiver-facing egress AF_PACKET metadata와 network integrity를 검사하며 N05나 `verify`를 실행하지 않습니다.

G006 당시 통합 작업 트리에서는 57×20=1,140회가 통과했습니다. runner 시작 race와 strict ledger reader 수리 뒤 G007 동결 트리는 58×20=1,160회, M5 CLI 상호운용 트리는 70×20=1,400회 통과했습니다. OpenSSL callback/native I/O 경로를 더한 현재 동결 트리는 72×20=1,440회와 11개 부품 include 경계 검사, 생산 번역 단위 24개의 cppcheck·clang-tidy를 통과했습니다. M6 제품 코드 review는 APPROVE, 구조 검토는 CLEAR였고 normal/external 원자료 감사도 통과했습니다. 각 시점의 실패와 증거는 `docs/validation.md`에 따로 보존합니다.

## 통합 검토 후 추가 확인

문자열을 돌려주는 협상 결과 조회는 핑퐁의 마지막 호출 완료 뒤에 실행합니다. 따라서 버전·암호 방식·그룹·서명 이름을 만드는 할당이 주 측정 구간에 들어가지 않습니다. 실제로 관측된 암호 방식·그룹·서명은 요청 프로필과 비교하며, 빈 값은 요청값으로 채우지 않고 관측하지 못했다는 설명을 남깁니다. 호출 완료 사건에는 응용 바이트의 요청량과 실제 처리량도 기록합니다. 어댑터가 실패하면 제공된 오류 설명을 무효 이유에 보존합니다.

추가 시험에서 Mbed TLS 자체 연결과 OpenSSL/Mbed TLS 양방향 교차 연결은 서버 인증·상호 인증 및 시간·메모리 모드를 통과했습니다. 협상 결과 조회가 측정 종료 뒤에 있고, 응용 바이트 합계가 요청량과 같은지도 검사했습니다. 기존 wolfSSL build3 모듈은 기본 자원 제한 상태에서 `wolfSSL_new failed`를 반환했고 제한을 끈 비교 실행에서는 통과했습니다. 이 문제는 어댑터 담당자에게 전달했으며, 제한을 몰래 끄거나 기본 정상 경로 성공으로 보고하지 않습니다.

최종 통합에서 wolfSSL을 공식 `WOLFSSL_GETRANDOM` 빌드 조건으로 다시 빌드하여 파일 생성 제한 안에서도 난수 준비가 가능해졌습니다. 현재 세 라이브러리의 모든 교차 연결이 기본 자원 제한에서 통과합니다. 위 실패 기록은 원인 확인 과정으로 보존합니다.

CPU 고정을 요청했으면 실패를 경고만 남기고 진행하지 않습니다. 역할 또는 지휘 프로세스의 고정 실패는 표본을 무효로 만듭니다. `pinned_cpu`는 실제 성공한 CPU 번호이며, 고정하지 않았거나 실패했으면 -1입니다. 지휘 프로세스의 실패는 `director.txt`에 남고 역할 기록의 성공 여부보다 우선합니다. 테스트 전용 링크 래퍼로 고정 실패를 재현해 이 규칙을 검사하며 프로덕션 코드에는 오류 주입 경로를 넣지 않았습니다.
