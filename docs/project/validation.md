# 현재 구조의 검증 기록

2026년 11월 12일, x86_64 WSL2에서 독립 엔드포인트와 현재 형식의 정상 실행을 확인했습니다. 아래 결과는 `artifacts/refactor-current/`에 명령·로그·원자료·바이너리 지문과 함께 보존합니다. 과거 구조의 결과를 현재 시험 수나 독립 표본 수에 합치지 않습니다.

## 빌드와 회귀

별도 `tests/` 빌드의 전체 86개 검사는 실제 세 라이브러리의 TLS, 서버 인증·상호 인증, 네 시나리오·두 송신 정책, 부분 입출력·큰 양방향 데이터, 독립 준비 상태, 조회·컨텍스트 반복·BiTHaC·ML-KEM·netem·송신 시각·분석을 포함합니다. 이전 87개에서 삭제한 한 검사는 사용하지 않는 C++ 시도 원장 작성기 시험입니다. 시도 원장은 외부 실행기의 통합 시험으로 확인합니다. 가짜 어댑터의 성공을 실제 TLS 성공으로 세지 않습니다.

소스와 시험 빌드는 별도이며 경고를 오류로 취급했습니다. 릴리스 구성 8개에서 내장 OpenSSL·wolfSSL·Mbed TLS, 모듈과 분석 도구를 빌드했습니다. 클라이언트 전용 wolfSSL·서버 전용 Mbed TLS·빈 TLS 의존성 경로의 모듈 클라이언트·분석 전용 구성을 다시 구성하고 생성된 실행 파일 목록과 실제 동적 의존성을 확인했습니다. 앞의 세 전용 구성에서는 OpenSSL 탐색을 비활성화했습니다. [빌드 명령](../../artifacts/refactor-current/builds.json), [마지막 소스 빌드](../../artifacts/refactor-current/build-refresh.json), [독립 구성·링크 확인](../../artifacts/refactor-current/build-isolation.json).

cppcheck와 clang-analyzer는 외부 소스를 제외한 프로젝트 번역 단위를 검사합니다. 11개 부품의 헤더 포함 경계·순환 의존 검사와 자체 시험, Python 구문·셸 구문·문서 링크·공백 검사도 검증 목록에 포함합니다. 결과는 [전체 검증 목록](../../artifacts/refactor-current/verification.json)과 [회귀 로그](../../artifacts/refactor-current/logs/ctest-final.log), [정적 검사 로그](../../artifacts/refactor-current/logs/static.log)를 따릅니다.

## 실제 독립 연결과 네트워크

릴리스 실행 96쌍은 같은 라이브러리의 내장 연결 48쌍, 양방향 내장/모듈 혼합 24쌍, 라이브러리 간 내장 연결 24쌍입니다. 네 시나리오를 모두 수행했고 같은 라이브러리 내장 실행에서는 두 인증·두 송신 정책을 조합했습니다. 자기 작업·출력 폴더, wildcard 수신·루프백 접속, 준비 요약, 첫 측정 연결, 해독과 양쪽 보고를 확인했습니다. TLS schema 3·제어 프로토콜 2를 기록하고 관측 없는 실행에는 부모 관측 소켓을 만들지 않았습니다. [96쌍의 명령과 결과](../../artifacts/refactor-current/pairs/verification.json).

veth 두 쌍의 양방향 10ms 지연 실행에서 TLS TCP는 1개, 제어 TCP는 1개였습니다. 한 라우터 인터페이스에서 관측한 TLS 데이터 68,191바이트는 양쪽 송신 원자료와 일치했고 제어 데이터 6,620바이트는 별도로 분류했습니다. 확인용 데이터 연결은 없었습니다. OpenSSL 클라이언트·Mbed TLS 서버의 두 연결에서는 양방향 첫 데이터 패킷을 각각 제거해 지정 손실 4건·커널 재전송 4건과 정상 TLS 완료를 확인했습니다. 손실 사건은 모두 TLS 데이터 포트에 대응하며 호스트 네트워크 불변과 소유 자원 정리를 확인했습니다. 이 수치는 해당 기능 검증 실행의 관측량입니다. [흐름·지연·손실 복구](../../artifacts/refactor-current/network.json).

회귀 중 임시 포트 44331의 TLS 데이터를 제어 흐름으로 잘못 분류한 오류를 발견했습니다. 서버 포트를 방향별로 대조하도록 수정했으며 TLS·조회 패킷의 포트 중첩 회귀 검사를 추가했습니다. 최초 실패 캡처를 수정한 판독기로 다시 처리해 같은 TLS 바이트의 대응을 확인했습니다. 실제 BPF 프로그램에도 12가지 양방향 포트 조건을 실행해 제어 흐름이 추적·손실 대상에서 제외되고 TLS 데이터의 첫 손실 뒤 재전송은 통과함을 확인했습니다. 이후 전체 회귀와 새 netem·커널 실행을 통과했습니다. [보존한 실패 로그](../../artifacts/refactor-current/logs/ctest-port-collision.log), [동일 캡처 재분석](../../artifacts/refactor-current/port-collision.json), [BPF 직접 실행](../../artifacts/refactor-current/kernel-flow-final.json).

## 계측과 자료 재생성

`cpu-clock:u` CPU 표본은 내장 쌍 2시도와 모듈 OpenSSL 클라이언트·내장 Mbed TLS 서버 2시도에서 별도로 수집했습니다. 내장은 `context-setup-to-teardown`, 모듈은 `module-to-teardown`으로 시작 경계를 구별합니다. 주 구간에 표본이 없는 경우는 `missing`으로 남기고 0비용으로 해석하지 않습니다. `cpu-clock`은 PMU 사이클 계수의 대체값이 아닙니다. [내장 수집](../../artifacts/refactor-current/cpu-builtin/cpu-profile.json), [혼합 수집](../../artifacts/refactor-current/cpu-mixed/cpu-profile.json).

첫 내장 CPU 실행의 TLS·수집은 성공했지만 후처리기가 `SETUP_BEGIN`을 잘못 찾아 분석에 실패했습니다. 사건 선택을 수정한 뒤 같은 `perf.data`를 재분석했습니다. 실패 로그와 최초 명령을 남겼으며 TLS 표본을 교체하지 않았습니다. [최초 분석 실패](../../artifacts/refactor-current/logs/cpu.log), [수정 뒤 분석](../../artifacts/refactor-current/logs/cpu-reanalysis.log).

판독기는 TLS schema 1·2와 측정 계약 누락을 거절합니다. 현재 자료의 종료 사건·가용성·명시적 null·필드 누락·실제 0을 구별합니다. 보고서는 선택한 파일의 실행·컨텍스트 ID를 대조하며 TCP 부가 분석도 해독 파일의 ID를 확인합니다. 조회 보고서는 요청한 분모를 보존하기 위해 `attempts.jsonl`을 요구합니다. 원자료 불변·보고서 재생성 확인은 [재분석 결과](../../artifacts/refactor-current/replay.json)에 있습니다.

## 재확인 명령

```sh
cmake --build build-tests-independent --parallel 4
ctest --test-dir build-tests-independent --output-on-failure --parallel 4
scripts/static-check.sh build-module "$PWD" all
python3 scripts/check-modules.py
python3 scripts/check-modules.py --self-test
python3 scripts/implementation-report.py \
  --verification artifacts/refactor-current/verification.json
```

새 환경에서는 먼저 [README](../../README.md)에 따라 의존성과 소스·별도 시험 빌드를 준비합니다. 검사는 의존성을 내려받지 않습니다. 보존된 원자료의 재분석에는 관리자 권한이 필요하지 않지만, 새 커널 BPF 수집은 지원되는 권한·도구를 필요로 합니다.

커널 흐름 분류의 직접 검사는 BPF가 허용된 환경에서 별도로 실행합니다. 아래 검사는 프로그램을 커널에 적재하고 `BPF_PROG_TEST_RUN`으로 패킷을 입력하며 인터페이스에 부착하지 않습니다. 기본 86개 CTest와 구별합니다.

```sh
python3 scripts/build-kernel-observer.py --output build-module/kernel-observer.bpf.o
python3 tests/integration/kernel_flow.py --object build-module/kernel-observer.bpf.o
```

## 완료 판정의 한계

WSL의 루프백·veth 기능 검증입니다. 물리 NIC 경로, 실제 ARM 툴체인·장비, 네이티브 Linux 본 성능 실험, 배포 크기·RSS 계측은 미검증입니다. 원격 배포·프로세스 재시작·결과 회수는 외부 실행 환경의 책임입니다. 강건성·공격·인증서 거절·타이밍 누출 시험은 추가하지 않았습니다. 본 연구의 성능 결론과 논문 수치 재현 여부는 별도로 판정합니다.

## 계측 의도와 실제 동작의 대조

같은 날짜의 후속 검증입니다. 앞의 독립 엔드포인트 검증은 개정 3의 기준선이며, 이번 새 TLS 실행은 합의한 마지막 TLS API 성공 반환을 종료점으로 쓰는 개정 4입니다. ABI 3·schema 3·제어 프로토콜 2는 유지합니다. [종료 의미와 포함 비용](../design/runtime.md#시나리오의-종료-개정-4), [변경 결정](DECISIONS.md#마지막-tls-api-반환과-계측-증거-2026년-11월-12일)을 기준으로 판정했습니다.

기준선의 수정된 작업 트리 전체 218개 파일과 diff·지문·빌드 정보를 `results/measurement-audit-20261112/`의 `baseline-source.tar.gz`, `baseline-diff.patch`, `baseline-manifest.json`에 보존했습니다. 기존 사용자 변경은 되돌리지 않았습니다. 수정 전 전체 86개 CTest는 통과했으나 아래 계측 보고 오류를 검출하지 못했습니다. 이 사실을 “버그 없음”의 근거로 쓰지 않습니다.

### 계약과 검증표

표의 ns는 해당 엔드포인트의 단조 시계 또는 작업 스레드 CPU 시계입니다. 상대 엔드포인트의 절대 시각을 빼지 않습니다. 카운터는 시간으로 환산하지 않고, 힙 바이트는 할당 훅의 요청량이며 RSS·스택과 다릅니다. 원자료의 독립 계산 결과는 [306쌍의 검증 목록](../../results/measurement-audit-20261112/matrix-release/verification.json)에 역할·연결·시작·끝 순번과 함께 저장했습니다.

| 대상·단위·역할·시계 | 계약·원자료·독립 기대값 | 구현·검증 근거와 판정 |
|---|---|---|
| 주 구간 경과 ns, 클라이언트·서버 단조 시계 | 클라이언트 첫 handshake 호출, 서버 첫 성공 TLS 수신 반환에서 역할별 마지막 성공 `CALL_END`까지. 끝−시작. API 처리 완료, Finished 내부 처리, 소켓 제출과 정리를 구별 | `role_runtime.cpp`, `report/window.cpp`; `measurement_evidence_scenario_end`와 실제 네 시나리오의 사건 선택 대조. 개정 4에서 완료 뒤 표식은 종료로 거절. 관측자 끔·직접 소켓 서버는 첫 수신이 없어 미관측 |
| 경과 분해 ns, 같은 역할의 단조 시계 | I/O·대기·호출의 닫힌 구간을 별도로 합산. 연산=호출−I/O, 틈=전체−호출−대기. 내부 중첩 표식은 다시 더하지 않음 | 고정 사건열은 전체 100, 연산 40, I/O 20, 대기 30, 틈 10. 실제 계산은 보고서 분할 함수를 재사용하지 않음. 순번이 빠지면 분해를 null로 처리. `computation`에는 계측·복귀와 프레임워크 호출 비용도 남음 |
| 포함·제외 작업, 양 역할 | 모듈·컨텍스트·TCP·연결 준비와 제어 준비는 주 구간 앞. 서버의 첫 수신 복사는 시작 앞. 이후 복사는 I/O 안. 페이로드 준비·앞선 수신 패턴 확인은 경계 안에 있으면 포함. 최종 패턴 확인·협상 조회·제어 완료·출력·정리는 밖 | `Capture`의 읽기 시점에서 예약·복사가 끝났는지 결정적 시험. 마지막 호출 뒤 사건 순서와 실제 TLS 교차 대조. 순수 TLS 함수 비용이라고 부르지 않음. 소켓 `close()`만의 비용은 별도 계측하지 않음 |
| 스레드 CPU ns, 같은 엔드포인트 스레드 | 마지막−첫 스레드 CPU 스냅샷. 누락·역행은 null이며 경과 시간이 있으면 따로 보존 | `measure_snapshot_brackets`의 시스템 시계 전후 읽기와 제어된 대기·연산. 내부 구간 CPU 누락 시 보고 중단을 수정. 절대 나노초 정확도·다른 스레드 CPU는 입증하지 않음 |
| PMU cycles·instructions·enabled/running ns | 같은 스레드의 그룹 읽기→CPU→단조 시계→힙 순서. 요청·실제 범위, 초기 설정 실패, 사건별 읽기 누락, 다중화를 구별. 비례 확대하지 않음 | `measure`의 시스템 호출 대역으로 속성·실패 단계·정리·계산 확인. [최초 일반 권한 실행](../../results/measurement-audit-20261112/pmu/verification.json)의 user+kernel은 EACCES로 무효. [후속 관리자 실행](../../results/measurement-audit-20261112/privileged-followup/independent-verification.json)은 세 라이브러리·두 범위에서 양 역할의 양수 계수, enabled=running, 원자료 차분과 보고값 일치를 확인. 네이티브 PMU 정확도 검증은 아님 |
| 힙 현재·누적·구간 최고 바이트, 엔드포인트 할당 도메인 | 시작의 live와 이후 독립 스냅샷 interval_peak의 최댓값. 시작 이전 최고치 제외. `KERNEL_RX`는 반환 스냅샷 복사본이라 제외. 하나라도 누락되면 최고치 null | 100 할당→7 재할당의 누적 107, 할당 2·해제 1, 마지막 해제 뒤 live 0·구간 최고 7→0. 보정·조회 도메인 읽기는 TLS 최고치를 초기화하지 않음. 동일 tick의 최고치 57과 시작 이전 1000 제외 회귀. 실제 메모리 모드 96쌍과 경계 크기 18쌍 대조 |
| TLS 스트림 바이트, 연결·방향별 | 성공한 부분 반환만 누적. 2+재시도 0+1=3. `OUTPUT_ACCEPTED`는 버퍼 수용이라 송신 바이트에 더하지 않음 | `lifecycle_capture_return_order`, `output_batch_partial_submission`, 실제 양쪽 sent=상대 received 및 I/O 범위=파일 길이. 버퍼 배치·TLS 레코드·TCP 패킷을 같은 단위로 취급하지 않음 |
| 레코드·메시지·소켓 제출 구간, 양 역할 | 레코드 외피의 바이트 범위와 성공 I/O 반환을 대응. 평문 알림은 시각 없는 순서 대조 자료 | 모든 조합의 해독·Finished 개수·방향별 응용 길이 확인. OpenSSL 평문 알림과 해독 순서 일치. 다른 두 라이브러리의 평문 알림은 미지원. [새 지연 pcap 대조](../../results/measurement-audit-20261112/network/packet-verification.json)는 바이트·흐름 근거이며 시각 동일성 증거가 아님 |
| 내부 연산 구간 ns, 라이브러리 훅 | 동일 연결·연산·메시지 ID의 begin/end. 정상 짝과 시각 순서를 확인하며 중첩 비용을 합산하지 않음 | 세 고정 소스의 패치에서 OpenSSL 상태 머신·`tls13_cipher`, wolfSSL 생성·넓은 송신·레코드, Mbed TLS 바디·fetch 뒤 처리·레코드를 대조. 실제 trace 시험에서 생성 구간 내 I/O·레코드 암호화 부재 확인. 짝 완결성은 라이브러리 전체 관측의 증거가 아님 |
| 모듈·컨텍스트·TCP·open·응용 진단 ns | 각 이름의 명시적 begin/end 차분. 모듈·컨텍스트는 연결 0에만 귀속. builtin 모듈 로드는 `not_applicable` | 내장·모듈 306쌍의 상태와 사건 대조. 추적 끔은 `unsupported`, 지원하지만 사건이 빠지면 `missing`. 가용성이 없는 값을 실제 0으로 바꾸지 않음 |
| 실행·컨텍스트·연결 ID와 통계 표본 수 | 요청 연결 수·warmup 위치·첫 측정 연결 보존. 위치별 그룹에 컨텍스트당 값 1개. 실패를 성공으로 대체하지 않음 | `measurement_raw_evidence`, `report_repeated_context`, 실행 원장 시험. 상대 헤더만 있고 사건이 없으면 자기 설명용 값은 유지하되 비교 제외. 개정 3·4는 같은 수치라도 별도 그룹 |
| 기한·자원 수명·조회·연구 기능 | 재시도에 같은 기한, 연결→컨텍스트→서비스·모듈 정리. 조회 힙 분리. BiTHaC 캐시와 ML-KEM 실제 분기만 해당 구현으로 판정 | 기존 전체 CTest의 부분 입출력·기한·조회·캐시·KEM·혼합 라이브러리·OpenSSL CLI 검사를 유지. ASan/UBSan은 수명 검사이며 계측 정확도 근거로 대체하지 않음 |

### 재현한 오류와 수정

다음 여덟 오류는 기존 구현의 관측·보고 의도를 복구한 수정입니다. 마지막 API 반환으로 끝내는 개정 4의 변경은 이 오류 수정과 구별합니다.

| 오류 | 수정 전 재현과 수정 후 확인 |
|---|---|
| I/O 사건 쌍 누락을 연산으로 흡수 | `measurement_evidence_io_missing`: 합계가 보존돼도 순번 공백을 검출하고 I/O·연산·대기·틈을 null로 남김 |
| 힙 일부 누락을 전체 최고치로 보고 | `measurement_evidence_heap_missing`, 실제 원자료 복사본의 `heap_missing`: 부분 최고치를 통계에서 제외. 모두 관측한 0은 0으로 유지 |
| 같은 tick 또는 비경계 스냅샷의 힙 최고치 소실 | `measurement_evidence_heap_equal_time`: 시각의 엄격한 대소 대신 순번과 실제 읽기 구간을 사용 |
| 내부 구간의 CPU 필드 누락 시 보고 전체 중단 | `measurement_evidence_span_cpu_missing`: 경과 10은 유지하고 CPU만 null·누락 이유 표시 |
| 시간이 역전된 내부 구간을 완전·가용으로 표시 | `measurement_evidence_span_order`: 짝이 있어도 시간 역전이면 `missing`·불완전 |
| 상대 헤더만으로 비교 적격 판정 | 실제 자료 복사본의 `peer_events_missing`: 상대 사건 완결성 확인과 `peer_measurement_incomplete` 제외 이유 |
| 요청한 연결의 일부가 사라져도 실행 성공 판정 | `connection_missing`: 요청 수·순서·warmup·완료 상태 대조, 무효 이유 보존 |
| 서버 Ping 공통 구간의 송수신 설명이 반대 | 수치는 마지막 Pong 처리로 계산했지만 그룹 메타데이터는 client-request 방향을 고정. 네 시나리오의 설명도 실제 호출에 맞춤 |

[최초 다섯 실패 로그](../../results/measurement-audit-20261112/regressions-before.log), [실제 원자료 복사본의 수정 전 결과](../../results/measurement-audit-20261112/raw-regressions-before/verification.json), [잘못된 송수신 설명](../../results/measurement-audit-20261112/directional-metadata-before.json)을 보존합니다. 기존 시험 중 부분 힙이나 상대 헤더만으로 성공을 기대하던 자료도 완전한 원자료로 바꿨습니다.

수정 과정에서 첫 수신의 공유 `KERNEL_RX` 스냅샷을 독립 읽기처럼 취급하면 시작 이전 최고치가 다시 들어오는 점을 고정 사건열로 추가 검출했습니다. [그 실패](../../results/measurement-audit-20261112/shared-snapshot-before.log)도 남기고 `measurement_evidence_heap_shared_rx_snapshot`으로 막았습니다. 시험 자체가 잘못된 종료점·중복 바이트·중복 연산·누락의 0 처리를 검출하는지도 복사한 자료로 확인했습니다. 실제 실패 자료를 변형하여 통과시키지 않았습니다.

### 이번 실행 결과와 제한

최종 별도 시험 빌드는 **97/97 CTest**를 통과했습니다. [전체 로그](../../results/measurement-audit-20261112/ctest-final.log)는 실제 TLS·혼합 라이브러리·직접 소켓·관측자 끔·연결 재사용·netem·조회·BiTHaC·ML-KEM과 새 회귀를 포함합니다. Release 역할별 구성 8개, cppcheck·clang-analyzer, 11개 부품 경계·순환 검사, Python·셸 구문·공백을 확인했습니다. [빌드 목록](../../results/measurement-audit-20261112/builds.json), [정적 검사](../../results/measurement-audit-20261112/static-final.log), [구조 검사](../../results/measurement-audit-20261112/structural-checks.json)를 따릅니다.

세 라이브러리 × builtin/module × 네 시나리오 × 두 인증 × 두 송신 정책 × timing/memory/trace의 **288쌍**을 모두 새 프로세스로 실행했습니다. 기본은 warmups=0·connections=1입니다. 별도로 방향별 크기를 16,383/16,384, 16,384/16,385, 16,385/16,386바이트로 주고 warmups=1·connections=2인 **18쌍**을 실행했습니다. 합계 306쌍이며 이 숫자를 성능 독립 표본 수로 해석하지 않습니다. 최종 보고기로 같은 원자료를 다시 검증하고 바이트·JSONL·키 로그의 SHA-256 불변을 확인했습니다. `report-before-final-heap/`도 보존했습니다.

새 veth 실행은 양방향 10ms 지연, 상호 인증, 두 연결로 세 라이브러리를 확인했습니다. TLS 원자료와 pcap 바이트 대응 및 제어 흐름 제외, 호스트 네트워크 불변과 소유 자원 정리를 확인했습니다. 최초 지정 손실·BPF 수집 시도는 `sudo: interactive authentication is required` 때문에 TLS 시작 전에 실행되지 않았습니다. [실패 명령과 로그](../../results/measurement-audit-20261112/network/execution-order.json)를 남기며 성공 표본으로 세지 않습니다. 당시에는 보존된 개정 3 자료의 양 방향 지정 제거 4건·재전송 4건을 재대조했습니다. 이후 사용자가 권한을 제공해 실행한 개정 4의 새 결과는 아래 후속 실측으로 구별합니다.

시스템 시계 전후 읽기와 제어된 대기·연산·할당을 [스냅샷 시험](../../results/measurement-audit-20261112/snapshot-brackets.log)으로 확인했습니다. 최초 일반 권한 실행에서는 user PMU의 실제 계수를 관측했고 user+kernel은 권한 때문에 미지원이었습니다. 후속 관리자 실측과 다중화·읽기 실패의 결정적 대역 시험을 구별해 기록합니다. 절대 시간 교정이나 물리 CPU의 정확한 명령 수를 입증하지 않습니다.

ASan/UBSan 구성의 검사 15개(인증서 준비 포함)와 OpenSSL 상호 인증·메모리 모드의 실제 두 연결이 통과했습니다. [부품 검사](../../results/measurement-audit-20261112/sanitizer-tests.log), [전송·캡처 검사](../../results/measurement-audit-20261112/sanitizer-transport.log), [실제 TLS 결과](../../results/measurement-audit-20261112/sanitizer-tls-no-lsan/verification.json)를 보존합니다. 최초 엔드포인트 실행에서는 `RLIMIT_NPROC=0` 때문에 LeakSanitizer 보조 프로세스를 만들지 못했습니다. 그 [최초 로그](../../results/measurement-audit-20261112/sanitizer-tls/client.log)를 보존하고 엔드포인트 실행에만 `ASAN_OPTIONS=detect_leaks=0`을 지정했습니다. 부품의 할당 수명 검사는 누수 검사를 유지합니다. 외부 TLS 라이브러리 전체를 sanitizer로 다시 빌드한 것은 아닙니다.

ARM·물리 NIC·네이티브 Linux 성능 실험·외부 기준의 절대 시간 교정은 이번 완료 조건 밖이며 미검증입니다. 라이브러리 내부의 표식 밖 작업과 정확한 소켓 정리 비용도 관측했다고 주장하지 않습니다. 강건성·공격·잘못된 인증서·타이밍 누출 시험은 추가하지 않았습니다.

재생성 시에는 기존 산출물을 덮어쓰지 않는 새 출력 경로를 지정합니다.

```sh
cmake --build build-tests-independent --parallel 4
ctest --test-dir build-tests-independent --output-on-failure --parallel 4
python3 -B tests/integration/measurement_audit.py \
  --build build-module --pki build-tests-independent/pki \
  --builtin openssl=build-endpoint --builtin wolfssl=build-client-wolf \
  --builtin mbedtls=build-server-mbed --output results/measurement-audit-new
scripts/static-check.sh build-module "$PWD" all
```

### 권한 제공 뒤 추가 실측

사용자가 관리자 인증을 제공한 뒤, 이전 실패 자료를 유지하고 `results/measurement-audit-20261112/privileged-followup/`에서 새로 실행했습니다. 기능 코드는 수정하지 않았습니다. 이 실행은 initial user namespace의 UID 0 조건이며, 일반 권한 실행과 합쳐 성능을 비교하지 않습니다. [실행 조건](../../results/measurement-audit-20261112/privileged-followup/conditions.json)에 남긴 `perf_event_paranoid=2`, `kptr_restrict=1`, `unprivileged_bpf_disabled=2`는 전후가 같고 전역 설정을 완화하지 않았습니다.

지정 손실은 세 라이브러리 각각 상호 인증·양방향 32KiB·컨텍스트당 두 연결·양방향 10ms 지연에서 확인했습니다. 양 방향 TLS 스트림의 0번 바이트를 포함한 첫 패킷을 연결마다 한 번 제거했습니다. 총 6개 TLS 연결의 **12건 제거 모두 같은 바이트 범위의 후속 커널 재전송 12건과 대응**했고 응용 검증까지 완료했습니다. [커널 검증 결과](../../results/measurement-audit-20261112/privileged-followup/network/verification.json)는 12개 역할/연결 행과 실패 0건을 남깁니다. 원본 pcap과 TLS 바이트가 일치하고, ring·사용자 버퍼 누락은 0이며 BPF·관측기·네임스페이스 정리와 호스트 네트워크 불변을 확인했습니다. 별도의 [실제 BPF 흐름 검사](../../results/measurement-audit-20261112/privileged-followup/bpf-flow-execution.json)도 정상 포트 중첩 12개 사례에서 데이터 흐름만 추적·제거하고 제어 흐름을 유지했습니다.

PMU는 같은 관리자 조건에서 세 라이브러리 × `user`/`user+kernel`의 6개 핸드셰이크 쌍을 실행했습니다. 양 역할 모두 요청 범위와 실제 범위가 같고, cycles·instructions와 enabled/running의 양수 차분을 얻었습니다. 이번 읽기에서는 enabled와 running 차분이 같아 다중화가 관측되지 않았습니다. [독립 대조](../../results/measurement-audit-20261112/privileged-followup/independent-verification.json)는 네트워크 3쌍과 PMU 6쌍, 총 24개 역할/연결에서 마지막 성공 API 반환·시간 분해·PMU 차분·보고 조건을 확인하고 원자료 SHA-256 불변을 남깁니다. 일반 권한의 최초 EACCES 실패가 성공으로 바뀐 것은 아니며, 권한 조건을 달리한 별도 실측입니다.

실제 OpenSSL 두 연결의 [추가 sanitizer 실행](../../results/measurement-audit-20261112/privileged-followup/sanitizer-verification.json)도 `detect_leaks=1:halt_on_error=1`로 통과했습니다. ASan·UBSan과 종료 시 누수 검사를 켜고 상호 인증·메모리 모드·Finished+Ping·ServerHello 분리 송신·32KiB 경계 초과 페이로드를 확인했습니다. 일반 권한에서 `RLIMIT_NPROC=0`으로 LeakSanitizer 보조 프로세스를 만들지 못한 최초 결과는 보존합니다. 관리자 진단의 성공을 일반 권한의 누수 검사 성공이나 외부 TLS 라이브러리 전체의 sanitizer 검증으로 확대하지 않습니다.

## 로컬 웹·새 경로 재현의 후속 검증

2026년 11월 12일 후속 작업에서 기존 97개 CTest와 새 고정 의존성 경로의 94개 CTest, 세 라이브러리 × builtin/module × 네 시나리오의 실제 설치 실행 24쌍을 확인했습니다. 웹이 생성한 프로필·CLI 명령과 결과 재가져오기도 별도로 검증합니다. 보관 목록·명령·정확한 조건과 관측 한계는 [로컬 웹·재현 기록](local-web-reproduction.md)을 따릅니다. 앞의 이전 검증·실패 근거는 변경하지 않고 보존합니다.

## 공통 빌드 헬퍼의 후속 검증

`scripts/build.sh`로 module·tests·builtin OpenSSL·wolfSSL 클라이언트 전용·Mbed TLS 서버 전용·analysis의 여섯 구성을 실제 빌드했습니다. 역할 전용 빌드에 상대 역할·분석 실행 파일이 생성되지 않고, 분석 전용 빌드에는 엔드포인트 실행 파일이 없음을 확인했습니다. 변경한 `check.sh`에서 기존 97개와 새 빌드 호출 계약 1개, 합계 **98/98 CTest**가 통과했습니다. cppcheck, 부품 경계 11개, 셸 구문·변경 공백 검사도 통과했습니다. [전체 검사 로그](../../results/build-helpers-20261112/check.log)를 남깁니다.

새 빌드 호출 시험은 다른 작업 폴더·공백 포함 경로·별도 시험 폴더·의존성 선택·오류 시 호출 중단을 가짜 CMake/CTest로 확인하는 계약 시험입니다. 실제 TLS 근거는 별도로, 새 내장 OpenSSL 쌍과 wolfSSL 클라이언트·Mbed TLS 서버 쌍 각각 네 시나리오의 **8쌍**에서 TLS 1.3 전체 핸드셰이크·준비 1개·측정 2개 연결·양방향 경계 초과 페이로드를 확인했습니다. 새 분석 전용 빌드로 모두 해독·보고했고 무효 표본은 0개, 원자료 SHA-256은 불변입니다. [실제 TLS 결과](../../results/build-helpers-20261112/actual-tls.json)를 보존합니다.

검증에만 쓴 임시 빌드는 검사 뒤 삭제하고 CMake 설정·빌드 로그·인증서·원자료·보고서는 `results/build-helpers-20261112/`에 남깁니다. 저장소의 활성 빌드는 `build-module`과 `build-tests-independent`를 재사용했습니다. [검증 요약](../../results/build-helpers-20261112/verification.json)에 세부 범위를 기록합니다.
