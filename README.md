# TURTLE — 내 TLS 클라이언트 또는 서버 하나를 측정하기

TURTLE은 **이미 실행할 수 있는 TLS 응용**을 새 루프백 연결에서 시험한다. 사용자는 역할 하나와 실행 명령을 준다. 클라이언트면 서버를, 서버면 클라이언트를 맞은편에 준비한다. 기본 상대는 별도로 빌드하는 OpenSSL 피어다. 측정 대상의 소켓, TLS 상태, 오류 처리, 대기와 재시도는 응용이 계속 소유한다. TURTLE이 라이브러리 파일에서 시험용 응용을 만들어 주지는 않는다.

## 첫 실행: 수정하지 않은 GnuTLS 클라이언트

Linux, CMake 3.20+, C/C++20 도구 체인, nlohmann/json 3.12가 필요하다. 기본 피어에는 OpenSSL 개발 파일이, 로컬 시험 인증서 발급에는 `openssl` 명령이 필요하다. 이 예제는 별도로 설치한 `gnutls-cli`를 사용한다. 코어에 GnuTLS를 링크하지 않는다. 저장소 의존성 준비는 [고정 버전·해시 목록](tools/dependencies.json)을 참고한다.

~~~sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
./bench.sh --client gnutls-cli --logfile=/dev/stderr \
  --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3 '--verify-hostname={peer_name}' \
  '--x509cafile={ca}' '--x509certfile={cert}' '--x509keyfile={key}' \
  '--port={port}' '{host}'
~~~

기본값은 S3, mTLS, 예열 1회, 본 시행 2회다. 매 실행 새 시험 CA가 서로 다른 서버·클라이언트 인증서를 발급한다. 서버가 요청 `ping` 전체를 전달한 뒤에만 응답 `pong`을 공급하며, 클라이언트 stdout이 정확히 그 바이트인지 확인한다. `--logfile=/dev/stderr`는 GnuTLS 진단을 평문과 분리하는 **그 앱의 옵션**이다. 진단 문자열은 인증 증거로 쓰지 않는다.

결과 끝의 **`2 sample(s); 0 benchmark-qualified`는 예상된 결과**다. 수정하지 않은 GnuTLS로 요청·응답을 관측했지만 그 클라이언트의 TLS 호출 시각이나 PMU를 관측하지 않았다. 데이터 교환과 측정 자격을 구별한다. 명시한 필수 지표가 없거나 실제 실행이 실패하면 명령은 0이 아닌 상태로 끝난다. 인자 없는 `./bench.sh`는 별도 소켓 진단이지 TLS 실행이 아니다.

같은 실행을 파일로 고정하고 다시 분석하려면:

~~~sh
work=$(mktemp -d)
./build/turtle check examples/one-sided-s3.json
./build/turtle run examples/one-sided-s3.json "$work/run"
./build/turtle analyze "$work/run"
~~~

`check`는 프로필과 실행 파일을 확인하며 핸드셰이크 능력을 선언하지 않는다. `run`은 **새 출력 디렉터리**를 요구한다. 상대 경로를 포함한 `argv[0]`은 프로필 파일 위치 기준이고, 경로 구분자가 없는 명령은 PATH에서 찾는다. 인자를 셸로 재해석하지 않는다.

## 기존 응용의 참여 접점

- **역할과 평문:** `target.role`은 `client` 또는 `server`다. `argv`로 직접 실행하며 stdin에는 보낼 평문, stdout에는 수신·전달된 평문만 둔다. 줄바꿈, 프레임, 배너를 추가하지 않는다. 앱은 지정한 주소와 포트로 연결하거나 IPv4 루프백에서 리슨해야 한다.
- **설정:** `{host}`, `{port}`, `{ca}`, `{cert}`, `{key}`, `{peer_name}`은 문자열 치환이다. 앱의 실제 설정 문법·검증 방식은 그대로다. 서버 인증만 시험하면 클라이언트 인증서·키는 비어 있다. 사용하지 않는 옵션은 argv에 넣지 않는다.
- **상대:** 프로필에 `"peer": {"argv": [...]}`를 넣으면 반대 역할에서 그 명령을 실행한다. 측정 역할은 하나다. 생략할 때만 기본 피어를 쓴다. 기본 피어를 DUT로 지정할 수 없다. `-DTURTLE_BUILD_REFERENCE=OFF`로 코어와 관찰 SDK만 빌드·설치할 수 있고 이때 실행에는 별도 피어가 필요하다.
- **범위:** `scenario`는 S0(핸드셰이크), S1(클라이언트 단방향), S2(서버 선송신), S3(요청·응답), S4(선송신과 요청·응답)다. `auth`는 `server` 또는 `mtls`다. `application.request/greeting/response`로 해당 시나리오의 바이트를 지정한다. S2/S4는 별도 능력 시험과 **일반 시행의 실제 쓰기 순서**가 모두 필요하다. 평문을 받았다는 사실만으로 선송신으로 판정하지 않는다. [역할별 시나리오와 측정점](DESIGN.md#scenarios)

기본 CA 발급 대신 기존 PEM 시험 신원을 쓰려면 프로필에 아래처럼 추가한다. 경로는 프로필 기준이다. 이 경우 `openssl` 발급 명령이나 스크립트는 호출하지 않는다. `server_name`과 `client_name`은 각각 검증할 상대 이름이다. 서버 인증 전용이면 `client`를 생략할 수 있다. 공개 파일은 인증서 PEM 블록만 허용한다. 개인 키는 임시 전용 디렉터리에서만 사용하며 출력에는 **경로**가 남을 수 있지만 키 본문이나 키 해시를 보관하지 않는다.

~~~json
"credentials": {
  "ca": "pki/ca.crt", "server_name": "localhost", "client_name": "client.turtle.test",
  "server": {"cert": "pki/server.crt", "key": "pki/server.key"},
  "client": {"cert": "pki/client.crt", "key": "pki/client.key"}
}
~~~

## 양쪽이 준비된 뒤에 시작하는 측정

양쪽 역할의 TCP 연결·TLS 설정이 준비되기 전에 한쪽이 TLS를 시작한 시행을 동시 준비된 지연·PMU 표본으로 쓰지 않는다. 준비 시각을 **같은 Linux 시간 네임스페이스에서** 비교해, 양쪽 `ready`가 두 첫 TLS 진입보다 앞섰음이 확인되면 별도 동기화 호출은 필요 없다. 그렇지 않으면 엄밀한 시작을 원하는 응용은 준비 지점에서 [선택적 C API](include/turtle/start.h)를 한 번 호출할 수 있다.

~~~c
#include <turtle/observe.h>
#include <turtle/start.h>
/* 이미 TCP 연결과 이 연결의 TLS 설정이 준비된 지점 */
turtle_observe_event("ready");
int joint = turtle_wait_start();  /* 1: 공동 시작, 0: 미연동/해제, -1: 오류 */
/* joint != 1이어도 평소 응용 동작을 계속할 수 있다. */
/* 첫 실제 TLS 호출 직전에 별도로 hs_begin을 기록한다. */
~~~

이 API는 역할과 시나리오를 받지 않는다. 시작 전에 한 번만 기다리며 핸드셰이크, 평문 처리, 재시도 중에는 추가 장벽이 없다. 관찰용 fd는 여전히 단방향이다. 일반 stdin/stdout 참여에는 SDK나 준비 호출이 필요 없다. 한쪽이 준비 채널을 사용하지 않으면 하네스는 제한된 대기 뒤 동기화 없이 수행한다. 결과의 `prepared_start`는 실제 공동 해제, 독립적으로 확인한 준비 순서, 반증, 근거 부족을 구별한다. 로컬 TLS 시간은 남기지만 공통 시작 근거가 없으면 `benchmark_timing_ns`는 null이며 엄밀한 타이밍·PMU 표본이 아니다.

## TLS 의미 사건이 필요한 경우: 선택적 단방향 관찰

실행·평문 시험에는 TURTLE 코드를 링크할 필요가 없다. 실제 TLS 성공 반환, 인증 확인, 대상 스레드의 PMU나 전송 훅이 필요한 경우에만 **기존 앱의 해당 관측점**에서 [공개 C 헤더](include/turtle/observe.h)로 관찰 사실을 기록한다. 이벤트를 보내면 다음 동작이 돌아오는 인터페이스가 아니다. 예를 들어 앱이 이미 핸드셰이크 진입과 성공을 구별한다면:

~~~c
#include <turtle/observe.h>

/* 기존 핸드셰이크의 첫 TLS 호출 진입 직전, 한 번만. */
turtle_observe_event("hs_begin");

/* 별도 관측점: 실제 로컬 full-handshake 성공 반환 직후. */
turtle_observe_event("hs_complete");
~~~

위 두 호출만으로 인증이나 측정 자격을 선언할 수 없다. `write_attempt`는 실제 제시한 평문, `write_accepted`와 `read_return`은 실제 양수 반환된 평문 바이트, `validated`는 앱이 이미 내용을 검사한 바이트에만 쓴다. 이벤트에 시나리오 이름, CAD/SAD 레이블, 계산한 오프셋을 넣지 않는다. 하나의 읽기가 두 메시지에 걸칠 수도 있다. 프레임워크가 지정 평문과 범위를 대조한다. 관찰을 위해 소켓을 교체하거나 빌린 fd를 닫거나 옵션을 바꾸지 않는다. 누락은 미확인이다.

독립 C/CMake 프로젝트에서는 먼저 TURTLE을 설치하고 기존 대상에 관찰 라이브러리만 선택적으로 연결한다.

~~~sh
cmake --install build --prefix "$PWD/out/sdk"
# 앱의 평소 cmake configure 명령에 -DCMAKE_PREFIX_PATH="$PWD/out/sdk" 추가
~~~

~~~cmake
find_package(TURTLE CONFIG REQUIRED)
target_link_libraries(my_existing_app PRIVATE turtle::observe)
~~~

## 결과 읽기와 검증

- `manifest.json`: 실행 프로필, 선택한 대상·상대와 바이너리·인증 자료 식별자, 예열·능력 시험·본 시행 목록 및 원자료 해시.
- `attempt-N/attempt.json`: 연결 ID, 실제 argv/PID와 이미지 증거, 호스트가 기록한 평문 범위·시각·종료 상태. 역할별 `*.stdin`, `*.stdout`, `*.stderr`, `*.ndjson`은 서로 분리한다. 시험 개인 키는 결과에 복사하지 않는다.
- `analysis.json`: `measurement_count`는 본 시행 수, `successful_measurements`는 양쪽 과업 근거가 확인된 본 시행 수, `eligible_measurements`는 유효 측정 표본 수다. `application_exchange`는 응용 경계만, `scenario_support`는 실제 시나리오 입증 여부만 말한다. `collection_complete`는 회수를 끝냈다는 뜻이지 PMU 사용 가능이나 유효 표본을 뜻하지 않는다.
- 하드웨어 카운터·상세 기록은 해당 근거가 있을 때만 사용한다. `required_metrics`에 `"perf_counters"` 또는 `"scenario_wall_ns"` 등을 지정해 그 근거를 요구할 수 있다. `recording`의 `basic`·`detailed`는 프로필 호환용 값으로, 앱에 전달하거나 수집량을 전환하지 않는다. 두 값으로 기록 비용을 비교할 수 없으며 실제 제공한 관측과 필수 지표가 자격을 결정한다. 같은 대상 스레드의 시작·끝에서 cycles와 instructions를 함께 확인할 수 없으면 기본 표본으로 채택하지 않는다. 계수 하나만 확인됐거나 multiplex되어 전체 구간을 직접 세지 않았다면 관측한 원자료만 남긴다. 나머지 조건이 충족돼도 이 조합은 `decision_required`이며, 미계측을 0으로 채우지 않는다. 호스트 파이프 시각을 TLS 반환 시각으로 바꾸지 않는다. 망 조건은 실제 적용 근거가 있어야 한다. 적용하지 않은 조건으로 대체하지 않는다. [네이티브 TLS 검증과 재현](docs/native-validation.md)
- `turtle analyze RUN`은 대상 바이너리를 재실행하지 않고 저장한 근거로 판정을 재생성한다. 이전 형식의 보관 결과도 읽지만 이전 실행 명세를 라이브 대상 접점으로 사용하지 않는다. [예제 구분](examples/README.md) · [네이티브 인수 계약](docs/native-participant.md)

**선택 지표와 망:** `required_metrics`는 양성 근거를 요구하고 `optional_metrics`는 부재를 기록하되 실행을 막지 않는다. 예: `timing`(`scenario_wall_ns`), `pmu`(`perf_counters`), `task`, `peer_task`, `authentication`, `profile`(협상 조건), `message_timeline`, `ordinary_server_first`, `transport_counts`, `ciphertext_bytes`, `record_layout`(`records`), `timed_records`, `library_io`(`public_io`), `header_layout`(`headers`), `tls_flights`, `capture`, `tcp_ack`, `cpu_samples`. 오타는 거부하며 결과의 `requested_metrics`에서 근거가 없거나 모순인 지표를 구별한다. 이름 별칭 대신 표준 협상 ID(예: `expected.group: 4588`)로 요구할 수도 있다.

`task`는 측정 대상, `peer_task`는 그 반대편, `ordinary_server_first`는 어느 쪽을 측정하든 **서버의 본 시행**에서 확인한다. 예를 들어 클라이언트를 측정할 때 서버가 보고한 선송신은 쓸 수 있지만, 클라이언트의 성공으로 서버의 과업 증거를 대신하지 않는다.

루프백이 기본이다. 격리된 Linux 네트워크 네임스페이스·netem·캡처 권한이 있을 때 프로필에 다음 필드를 추가하면 추가 RTT 16 ms와 클라이언트→서버 손실 20%를 요청한다.

~~~json
"network":"netem", "netem":{"additional_rtt_ms":16,"client_to_server":{"loss_pct":20}}, "measurement":{"capture":true}, "required_metrics":["capture"]
~~~

`capture` 성공과 특정 사본의 `tcp_ack` 증명은 다르다. TCP 누적 ACK는 반대 방향 사본이 전송 계층에 도달했음을 연결할 수 있을 때만 근거가 되며 TLS 처리·인증·평문 검증 시각이 아니다. 망 조건 적용에 실패하면 루프백 결과로 대체하지 않는다.

**함수 프로파일:** `"measurement":{"cpu_samples":{"event":"cycles:u","frequency_hz":997}}`로 선택적 프로파일을 요청한다. 필수이면 `"required_metrics":["cpu_samples"]`도 지정한다. 기본 시행에서 perf를 실행하지 않는다. 별도 진단 대상 프로세스에 perf를 붙이고, 표본에서 해당 네이티브 시작·끝 사건과 같은 PID/TID·시간 범위만 고른다. `attempt-N/profile/`에는 실제 기록, ELF 식별 자료, 디코더 출력이 남는다. perf 부재·권한 거부·유효 구간 표본 부재는 함수 계수 0이 아니다. 재분석은 보관된 디코더 출력을 읽으며 보관된 도구 명령을 실행하지 않는다.

구형 보관 자료는 역할별 `perf.script.txt`와 당시 디코더의 성공 기록이 함께 있어야 한다. 둘 중 하나가 없으면 호스트의 perf로 다시 디코딩하지 않고 그 지표만 미확인으로 남긴다.

**신뢰 범위:** `run`과 `retry`는 사용자가 신뢰하는 로컬 프로그램을 계정 권한으로 실행한다. 대상의 단방향 사건은 해당 프로세스가 보고한 관측이며 원격 증명이나 악의적 응용에 대한 보안 인증이 아니다.

**실패 재시도:** `turtle retry OLD_RUN FAILED_CONNECTION_ID NEW_OUTPUT`는 완료된 로컬 실행의 실패한 **본 시행** 하나를 새 ID·새 연결에서 재시도한다. ID는 원 시행의 `attempt.json`이나 결과 행의 `connection_id`다. 원 결과를 덮어쓰거나 단순 미계측을 재시도 대상으로 간주하지 않는다. 원 시행을 만든 계정의 전용 영수증(`$XDG_STATE_HOME/turtle-retry`, 기본 `~/.local/state/turtle-retry`)과 입력·실행 파일 해시를 대조한다. 영수증이 없는 복사본과 변조·이동된 명세는 명령 실행 권한이 아니다. 저장 공간이 없어도 일반 시험과 오프라인 재분석은 가능하다. 가져온 자료는 분석만 하거나 직접 검토한 원 프로필을 새로 실행한다.

가령 평문 교환은 성공했지만 `cpu_samples` 진단을 얻지 못했다면, 이를 **필수**로 지정한 시행은 재시도 대상이다. **선택** 지표 누락만으로는 재시도하지 않는다. 두 경우 모두 원시 기록에서 최종 판정을 다시 계산하며, 원본의 `analysis.json`을 바꾸지 않는다.

일반 회귀 검사는 `ctest --test-dir build --output-on-failure`로 실행한다. 실제 제3 구현의 참여, 계측된 성능 표본, 물리 보드 측정은 각각 다른 검증이다.
