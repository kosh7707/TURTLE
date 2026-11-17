# perf 카운터와 CPU 표본 분석

TURTLE의 perf 계측은 공통 실행기와 네 핸드셰이크 관측 구간에 연결됩니다. `perf_event_open`은 구간별 cycles·instructions를 읽고, 별도의 `perf record` 실행은 어느 함수·모듈에서 CPU 표본이 관측됐는지 보여 줍니다. TLS 구현체의 공개 함수표, 라이브러리 내부와 메시지 콜백은 바꾸지 않습니다.

기본값은 두 기능 모두 꺼짐입니다. 구성을 명시하면 클라이언트와 서버에 각각 적용합니다. 각 반복은 새 프로세스·새 연결 하나이며 프로파일링을 위해 한 프로세스 안에서 연결을 재사용하지 않습니다. 일반 실행과 마찬가지로 실제 인증서 기반 TLS 1.3 전체 핸드셰이크와 암호화된 ping/pong을 수행합니다.

## 준비와 실행

카운터 수집에는 Linux perf_event API, PMU 지원과 호출 스레드의 이벤트를 열 권한이 필요합니다. 외부 `perf` 실행 파일은 CPU 표본 수집·분석에만 필요합니다. `readelf`는 당시 바이너리의 build ID를 확인합니다. 환경에서 하드웨어 이벤트를 수집할 수 없다면 이유와 errno를 남기며 소프트웨어 이벤트로 자동 전환하지 않습니다.

공식 Linux 7.0.14 소스의 perf를 Python 연결 없이 빌드한다. 준비와 버전·연결 의존성 확인은 [의존성 문서](dependencies.md)를 따른다. 실제 수집을 위해 시스템 perf 제한 값을 자동으로 바꾸지 않는다.

함수 이름을 확인하기 위해 실행 파일에 심볼을 남깁니다. 다음은 현재 저장소에 준비한 라이브러리를 사용하는 예입니다.

```sh
cmake -S . -B out/build/native -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_PREFIX_PATH="$PWD/.deps/native" \
  -DTURTLE_IMPLEMENTATION_DIRS="$PWD/implementations/openssl;$PWD/implementations/wolfssl" \
  -DOPENSSL_ROOT_DIR="$PWD/.deps/openssl-3.5.9/install" \
  -DWOLFSSL_ROOT_DIR="$PWD/.deps/wolfssl-5.9.4/install"
cmake --build out/build/native
```

기존 실행 명세의 각 `configurations[]`에 다음 설정 중 필요한 것을 넣습니다. 바이너리·인증서·그룹·네트워크 설정은 기존 형식 그대로입니다.

카운터만 수집하는 설정:

```json
"measurement": {"perf_counters": true}
```

CPU 표본을 별도 실행으로 수집하는 설정:

```json
"measurement": {
  "cpu_samples": {
    "perf": ".deps/native/bin/perf",
    "event": "cycles:u",
    "frequency_hz": 997
  }
}
```

표본 이벤트는 `cycles:u` 또는 `cpu-clock:u`를 명시적으로 선택합니다. 생략한 이벤트·주파수의 기본값은 `cycles:u`·997 Hz입니다. 실행 파일 경로를 생략하면 PATH의 `perf`를 찾습니다. 요청한 주파수를 사용할 수 없으면 실패하도록 `--strict-freq`를 지정하며, 실제 이벤트 속성은 `perf.events.txt`에 저장합니다. 현재 실제 검증은 997 Hz로 수행합니다. 주파수를 높여도 모든 짧은 구간에 표본이 생기는 것은 아닙니다.

[카운터 예제](../../examples/perf-counters.json)와 [CPU 표본 예제](../../examples/perf-sampling.json)는 README에서 준비한 `out/certificates/server.crt`·`out/certificates/server.key`와 위 `out/build/native`를 사용합니다. 예제는 loopback이고 네트워크 관측은 미수집입니다. 기존 netem 명세에도 같은 `measurement`를 사용할 수 있습니다.

```sh
out/build/native/turtle run examples/perf-counters.json out/runs/perf-counters
out/build/native/turtle run examples/perf-sampling.json out/runs/perf-sampling
out/build/native/turtle analyze out/runs/perf-sampling
python3 tools/report/report.py out/runs/perf-sampling out/runs/perf-sampling-report
```

출력은 새 디렉터리여야 합니다. perf 수집이 요청된 시도는 일반 시간·바이트 비교 집계에서 제외합니다. 해당 시도의 벽시계·스레드 CPU 시간과 바이트는 원자료와 `analysis.json`에 보존합니다. 카운터는 별도 `counter_report.csv`, CPU 표본은 `cpu_report.json`·`cpu_report.csv`에 내보내며 `report.md`·`report.html`에도 전용 표를 표시합니다. 실패한 시도를 지우거나 대체하지 않습니다.

## 하드웨어 카운터의 경계

호출 스레드에 cycles와 instructions를 하나의 이벤트 그룹으로 열고 커널·하이퍼바이저 실행과 다른 스레드의 상속은 제외합니다. 이벤트 ID로 두 값을 구별하고 그룹 읽기의 활성 시간과 실제 실행 시간을 함께 보존합니다. 그룹을 여는 작업과 기록 버퍼 확보는 prepare보다 앞에서 수행합니다. [Linux perf_event_open 문서](https://man7.org/linux/man-pages/man2/perf_event_open.2.html)

기존 시각을 기록한 직후 카운터 스냅샷을 읽습니다. 공개 호출·전송·소켓·프레임 사건의 시작과 끝에 연결하며, 준비·핸드셰이크·시나리오·첫 사용과 네 관측 구간의 차이를 계산합니다. 서버 시나리오 끝은 마지막 Pong 소켓 반환 사건의 스냅샷을 그대로 참조합니다. 네 구간의 경계도 기존 사건 ID와 시작/끝을 참조하므로 비슷한 시각을 찾아 추정하지 않습니다.

`cycles_raw`·`instructions_raw`는 실제 읽은 누적값의 차이입니다. `time_enabled_ns`와 `time_running_ns`의 차이도 보존합니다. 실행 시간이 양수이고 활성 시간과 같을 때만 `cycles`·`instructions`를 해당 구간 전체의 유효 지표로 채택합니다. 실행 시간이 0이거나 일부만 스케줄된 구간은 `missing`으로 남기고 원시 값에 배율을 곱해 전체 실행 비용으로 만들지 않습니다. 수집된 실제 0과 구별합니다.

네 구간의 원시 카운터·활성 시간·실행 시간 합이 전체 핸드셰이크와 일치하는지 확인합니다. 전송 콜백과 콜백 밖 구간의 합도 확인합니다. 공개 호출·전송·소켓·프레임은 겹치는 관측이므로 모두 더하지 않습니다. 하나의 전송 사건이 여러 레코드나 구간에 연결되더라도 카운터는 사건 ID당 한 번 저장합니다.

카운터 읽기 전후의 `CLOCK_MONOTONIC` 시각과 그 구간 합을 기록합니다. 이는 읽기 호출의 직접 벽시계 비용이며 전체 계측 비용이 아닙니다. 시각·카운터는 순차적으로 읽으므로 완전히 같은 명령어 경계를 뜻하지 않습니다. 사용자 공간의 계측 코드도 카운터에 포함됩니다. 직접 비용이나 프레임 비용을 빼서 계측 전의 성능으로 보정하지 않습니다.

## CPU 표본과 재분석

`perf record`가 각 엔드포인트를 실행합니다. `--clockid mono`의 표본 시각을 해당 엔드포인트의 PID·실제 호출 TID와 `CLOCK_MONOTONIC` 구간에 연결합니다. 다른 스레드의 표본은 제외한 개수를 따로 기록합니다. 시나리오, 공개 호출, 네 구간, 모든 사건과 콜백 밖 구간에 대한 보기를 제공합니다. 각 구간은 `[시작, 끝)`이므로 경계 위의 표본은 다음 구간에만 들어갑니다. 네 구간 표본 수의 합은 핸드셰이크 표본 수와 일치해야 합니다. [perf record 문서](https://man7.org/linux/man-pages/man1/perf-record.1.html)

출력은 함수·모듈의 표본 수, period 합과 period 비중입니다. 호출 횟수나 함수의 정확한 CPU 시간으로 환산하지 않습니다. 표본 시각의 명령어를 구간에 연결하는 것이며 그 표본의 period 전체가 같은 구간에서 발생했다고 보장하지 않습니다. 표본 없는 짧은 구간은 `no_samples_in_window`이고 내부 계산 비용 0이 아닙니다. 핸드셰이크와 하위 사건은 서로 포함되므로 그 표본 수를 더하지 않습니다.

수집 직후 `perf.data`, 버전, 실제 이벤트 속성, 기록 명령, build ID 목록과 실행 바이너리·공유 라이브러리의 사본을 보존합니다. 사본의 build ID를 기록 당시 값과 대조하고 SHA-256을 저장합니다. 분석은 보존한 `symbols/`를 `--symfs`로 지정하며 debuginfod 다운로드와 공유 build-ID 캐시 사용을 피합니다. 저장된 객체가 빠지거나 바뀌면 분석 미완료로 남깁니다. 현재 설치된 다른 라이브러리로 자동 보충하지 않습니다. [perf script 문서](https://man7.org/linux/man-pages/man1/perf-script.1.html)

VDSO 등 보존할 수 없는 객체와 해석되지 않은 심볼은 `[unknown]`으로 남깁니다. 잃어버린 사건과 해석하지 못한 출력 행을 저장하고 수집 완료로 인정하지 않습니다. `perf_complete`는 요청한 수집의 완료이며 TLS 성공·네 구간 완료·네트워크 완료와 별개입니다. CLI는 요청한 수집까지 완료해야 성공 코드 0을 반환합니다.

## 원자료 형식

공개 C 계약, TLS 스트림과 기존 사건 시각 형식은 그대로입니다. 새 엔드포인트는 `endpoint.json`의 `collection`에 수집 여부, 일반 표본 여부와 `counters_file`을 명시하고 호출 TID도 기록합니다. 별도의 `turtle.counters.v1` 파일을 사건 ID로 연결합니다. 이전 원자료의 카운터나 CPU 표본을 추정 복원하지 않습니다.

```text
attempts/00000/client/ 또는 server/
  endpoint.json             수집 표지와 호출 PID·TID
  events.jsonl              기존 공개 호출·전송·소켓·프레임 사건
  counters.json             요청·가용성·errno·누적값·그룹 시간·읽기 경계
  profile.json              별도 CPU 수집 설정·명령·객체 출처·수집 결과
  perf.data                 원본 perf 기록
  perf.events.txt           실제 이벤트 속성
  perf.header.txt           perf 기록 메타데이터
  perf.buildids.txt         기록된 객체의 build ID
  symbols/                  원래 절대 경로 구조를 보존한 바이너리·라이브러리
  perf.script.txt           보존 객체로 해석한 표본과 lost 사건
  cpu-samples.json           호출 스레드의 정수 시각·IP·함수·모듈·period
```

`counters.json`은 수집하지 않은 실행에도 `requested=false`·`not_collected`로 작성합니다. CPU 표본 관련 파일은 요청한 실행에서만 생성합니다. 성능 카운터 수집 불가·누락을 정상적인 0으로 기록하지 않습니다. 파생 보고서의 각 지표에는 유효 표본 수와 가용성별 개수가 있습니다.

## 검증

```sh
cmake -S tests -B out/tests/native -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_PREFIX_PATH="$PWD/.deps/native" \
  -DTURTLE_BINARY_DIR="$PWD/out/build/native" \
  -DTURTLE_TEST_OPENSSL=ON -DTURTLE_TEST_WOLFSSL=ON -DTURTLE_TEST_PERF=ON \
  -DTURTLE_PERF_EXECUTABLE="$PWD/.deps/native/bin/perf" \
  -DOPENSSL_ROOT_DIR="$PWD/.deps/openssl-3.5.9/install"
cmake --build out/tests/native
ctest --test-dir out/tests/native -R perf --output-on-failure
```

기본 `deterministic_analysis`는 실제 PMU 없이 큰 정수·부분 실행·미지원·실제 0·반열린 구간·period 가중치를 확인한다. 네 구간과 콜백 비용의 분할도 결정적으로 대조한다.

선택적 실제 시험은 OpenSSL·wolfSSL 각각에 카운터, `cpu-clock:u`, `cycles:u`를 수집한다. 수집 권한·이벤트·심볼 자료가 부족하면 실패한다. 측정값과 일반 통계 제외 판정은 C++에 있으며 Python 보고서는 분석 결과만 읽는다. 수행 결과와 제한은 [검증 기록](validation.md)에 있다.

재분석 시 기록한 perf 경로가 없으면 PATH에서 perf를 찾는다. Python 연결이 없는 네이티브 실행 파일이어야 하며 분석에 실제 사용한 경로와 해시를 분석 결과에 기록한다. 보존한 심볼 사본과 원자료의 무결성 검사는 그대로 적용한다.
