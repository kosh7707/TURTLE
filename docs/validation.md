# 검증 기록

아래 첫 기록은 2026년 10월 14일의 검증이며, 10월 15일 재개 결과는 마지막 절에 따로 남깁니다.

## 환경과 해석 범위

개발 환경은 WSL2의 Linux 6.6.87.2-microsoft-standard-WSL2, Intel Core i7-14700K, GCC 13.3.0입니다. 환경 점검에서 허용 논리 CPU 28개와 확인 가능한 물리 코어 대표 14개를 얻었습니다. 이 가상화 환경에서 perf 그룹은 `No such file or directory`로 열리지 않았으며, 주파수 정책과 Boost 비활성화도 확인하지 못했습니다. 해당 카운터는 0이 아니라 null로 남겼습니다.

아래는 **기능·기록 일관성 검증**입니다. 작업과 함께 실행한 WSL 수치로 라이브러리 성능 순위를 주장하지 않습니다. 단조 시계의 1ns 해상도도 1ns 측정 정확도를 의미하지 않습니다.

## 실행한 검사

| 검사 | 결과 |
|---|---|
| 엄격한 소스 빌드 | GCC `-Wall -Wextra -Wpedantic -Werror`, Release, 세 TLS 어댑터와 두 분석 도구 빌드가 통과했습니다. |
| 별도 테스트 빌드 | Debug 테스트 프로젝트가 통과했습니다. Release로 시험해도 assert가 사라지지 않게 설정했습니다. |
| 전체 반복 | `REPEAT=20 JOBS=4 scripts/check.sh`: **42개 시험, 각 20회, 총 840회 통과**했습니다. |
| 실제 TLS | 세 라이브러리의 3×3 클라이언트/서버 조합, 서버 인증과 상호 인증이 통과했습니다. |
| 전체 파이프라인 | 기본 자원 제한, 새 역할 프로세스, 준비 연결, 시간·메모리 모드, 실제 바이트 대응, 해독, 구간 합, 대체 경계, 원자료 재계산을 확인했습니다. |
| 티켓과 메시지 대조 | 같은 실제 TCP 실행에서 OpenSSL 메시지 알림과 해독 결과가 일치했고, 티켓 두 장과 Finished 송신 종료 구간을 확인했습니다. |
| 힙 수명 | 세 라이브러리의 셋업·정리 할당 시험에서 관측한 미해제 할당이 0개였습니다. 전체 핸드셰이크의 메모리 모드도 별도 통합 시험에 포함됩니다. |
| CPU 배치 회귀 | 테스트 전용 시스템 호출 래퍼로 고정 실패를 만들었습니다. 수정 전 실패를 확인하고, 수정 후 역할·지휘 실패가 무효 처리됨을 확인했습니다. |
| 통계 회귀 | StQ의 작은 표본 기준, 상대 CPU·판·빌드 구별, 상대 파일 부재, 묶음 불일치, 손상된 해독 보조 파일 진단이 통과했습니다. |
| 정적 검사 | `scripts/static-check.sh build "$PWD" all`: 선택한 cppcheck 및 clang-tidy 검사에서 통과했습니다. |
| 형식 검사 | clang-format 23.1.3의 저장소 규칙 dry-run과 `git diff --check`가 통과했습니다. 외부 코드는 제외했습니다. |
| 모듈 경계 | 정적 include 검사와 자체 시험이 통과했습니다. 생성한 CMake 링크 그래프 27개 노드에서 순환이 없었고, 네 어댑터 컴파일 명령에 내부 src include 경로가 없었습니다. |
| 코어 의존성 | `ldd build/turtle`에 libssl/libcrypto가 없음을 확인했습니다. 해독 도구와 OpenSSL 어댑터에만 필요한 연결을 둡니다. |
| 독립 코드 검토 | CPU 고정 실패·상대 식별·해독 진단·묶음 비교 관련 지적 네 개를 수정하고 회귀 시험을 추가했습니다. 재검토는 승인으로 끝났습니다. |

## 보존한 실행 자료

이 작업 공간의 `results/validation-20261014/`에 다음 자료가 있습니다. 생성 결과이므로 Git에서는 제외합니다.

- `check-42-final.log`: 840회 반복 실행과 모듈 검사 기록입니다.
- `static-final.log`: 두 정적 검사 도구의 실행 기록입니다.
- `cross-study/study.json`: 두 묶음에서 무작위화한 실행 순서와 명령입니다.
- `cross-study/batch-*/.../sample-*/`: 실제 측정 원자료입니다. **144개 측정 연결, 288개 역할 기록이 모두 유효**했습니다. 그중 144개 역할 기록은 힙 계측을 켠 실행입니다.
- `cross-study/report/summary.json`: 72개 분리된 그룹, 36개 같은 상대·프로필의 비교 후보, 무효 0개입니다. 보조 해독 파일 288개를 모두 확인했습니다. 비교 후보 수는 순위나 유의한 개선 수가 아닙니다.
- `tickets/`: OpenSSL 추적 모드 세 표본에서 각 두 장의 NewSessionTicket을 실제 해독한 자료와 보고서입니다.

원자료를 다시 요약하려면 다음과 같이 실행합니다.

```sh
./build/turtle-report results/validation-20261014/cross-study \
  results/validation-20261014/cross-study/report
```

새로 같은 **절차**를 실행하려면 새 출력 폴더를 지정합니다. 인증서·난수·시각과 성능 수치가 바이트 단위로 같아진다는 의미는 아닙니다.

```sh
python3 scripts/run-study.py --build build --pki pki/default \
  --samples 2 --batches 2 --cross --output results/new-check
```

## 확인하지 않은 것

물리 리눅스에서의 사이클·명령어 정확도, 하드웨어·송신 시각, 전체 스택 최고 사용량, 계측을 끈 독립 기준과의 영향 비교, 두 번째 독립 어댑터, 외부 연구 기법의 재현, 빈 운영체제에서의 설치 절차 검증은 포함하지 않았습니다. 저장소의 의존성 스크립트는 이 개발 환경에서 실제로 실행했지만, 이것을 새 운영체제 검증으로 바꾸어 쓰지 않습니다. 전체 파이프라인의 sanitizer 검증을 수행했다고도 주장하지 않습니다.

## 2026년 10월 15일 — 최초 작업 순서 재개

### 바꾼 범위

- 실행과 원자료: `src/model/model.hpp`, `src/config/config.cpp`, `src/transport/CMakeLists.txt`, `src/transport/channel.hpp`, `src/transport/channel.cpp`, `src/lifecycle/lifecycle.cpp`, `src/record/record.cpp`, `src/report/report.cpp`를 바꿨습니다. 소켓 설정 조회, 여러 측정 연결, 고정 컨텍스트 입력과 식별, 같은 연결 위치별 요약을 추가했습니다.
- 모의 구현: `implementations/mock/mock.cpp`에 8바이트 핸드셰이크 횟수 저장·복원을 추가했습니다. 실제 TLS 어댑터나 공개 어댑터 ABI는 바꾸지 않았습니다.
- 시험: `tests/config/config_test.cpp`, `tests/transport/transport_test.cpp`, `tests/lifecycle/CMakeLists.txt`, `tests/lifecycle/lifecycle_test.cpp`, `tests/lifecycle/probe.cpp`, 새 `tests/lifecycle/context_test.cpp`, `tests/record/record_test.cpp`, `tests/report/report_test.cpp`, `tests/integration/CMakeLists.txt`, `tests/integration/pipeline.py`, 새 `tests/integration/pki.py`를 추가하거나 보완했습니다.
- 문서: `README.md`, `docs/DECISIONS.md`, `docs/PROGRESS.md`, `docs/adapter-guide.md`, `docs/architecture.md`, `docs/record-format.md`, `docs/reporting.md`, 이 문서와 `docs/runtime.md`를 갱신했습니다.

별도 범용 지휘 프로토콜이나 새 외부 의존성은 만들지 않았습니다. 기존 함수표·파일 원자료·FNV 식별 함수를 재사용했습니다. 공개 계약은 유지하고, 원자료 형식 1에는 선택 필드를 추가했습니다. 예전 자료도 요약할 수 있지만 실제 소켓 설정이나 비어 있지 않은 컨텍스트 지문을 확인할 수 없으면 자동 비교에서는 제외합니다.

### 직접 확인한 결과

| 검사 | 결과 |
|---|---|
| M0 새 작업 폴더 | 변경 전 커밋을 새 로컬 checkout에서 기존 의존성만 사용해 빌드하고 42개 시험이 통과했습니다. 변경 내용을 옮긴 별도 소스·테스트 빌드 폴더에서도 45개 시험이 통과했습니다. 새 운영체제 설치 검증은 아닙니다. |
| 시험 선행 | 소켓 원자료 부재, 실제 설정이 다른 자료의 병합, 컨텍스트 저장 크기, 컨텍스트 입력 혼합, 측정 연결 누락, 미관측 소켓의 비교 허용이 수정 전 실패하는 것을 확인했습니다. |
| 현재 전체 검사 | `REPEAT=1 JOBS=4 scripts/check.sh`가 경고를 오류로 처리한 Release 소스·Debug 시험 빌드와 45개 시험을 통과했습니다. |
| 반복 검사 | 45개 시험을 각각 최대 20회 실행하도록 요청했습니다. **44개 시험은 각 20회, 총 880회 통과**했습니다. 인증서 매트릭스는 5회 통과 후 6번째에 실패했습니다. 전체 결과를 900회 통과로 보고하지 않습니다. |
| 실제 TLS | 기존 세 라이브러리의 3×3 연결과 OpenSSL 다중 측정 연결이 통과했습니다. 별도 생산 빌드 실행에서 코어를 고정한 wolfSSL 클라이언트/Mbed TLS 서버의 상호 인증을 시간·메모리 모드로 확인했습니다. 모드마다 표본 2개, 준비 연결 1개와 측정 연결 2개이며 보고 그룹 8개가 각각 독립 표본 2개를 담습니다. |
| M3 컨텍스트 | 모의 구현에서 빈 입력→저장값 1, 복원한 두 표본→각각 2, 역할별 입력 5/9→각각 6/10, 입력 지문 일치와 새 PID를 확인했습니다. 실제 TLS 상태 복원이나 세션 재개 성공 증거가 아닙니다. |
| 정적·문법 검사 | 생산 코드 18개 번역 단위의 cppcheck와 clang-tidy, 10개 부품의 정적 포함 경계, 셸 문법·Python 구문·`git diff --check`가 통과했습니다. |
| 독립 검토 | 미관측 소켓 비교 제외와 다중 연결 위치별 분리 지적을 반영한 뒤 이번 M0~M4 코드 범위는 승인됐습니다. 실행 환경의 시각 문제까지 해결했다는 뜻은 아닙니다. |

### 인증서 반복 시험에서 멈춘 이유

`local_pki_matrix`는 ECDSA P-256·RSA-2048·Ed25519 잎 공개키와 체인 길이 1~3의 9조합을 각각 두 번 생성합니다. CA의 키와 인증서 서명은 ECDSA이며, 키 종류와 서명 종류를 혼동하지 않습니다. 체인 순서, 서버·클라이언트 용도, 서버 호스트 이름을 실제 `openssl verify`로 확인합니다.

단회 전체 검사는 통과했지만 반복 검사에서 `certificate is not yet valid`가 발생했습니다. 앞선 진단 산출물에는 먼저 만든 루트의 유효 시작 시각이 `2026-10-15 01:39:27 UTC`, 뒤이어 만든 서버 인증서는 `01:39:22 UTC`로 남아 있습니다. 생성 도중 시스템 시각이 역행한 정황이며, 어떤 시간 동기화 구성요소가 원인인지는 확인하지 못했습니다. 인증서 검증을 끄거나 다른 검증 시각을 주입하거나 실패 표본을 성공으로 바꿔 채우지 않았습니다. 이 환경에서 M4의 반복 검증을 끝냈다고 표시하지 않습니다.

`results/validation-20261015-resume/`에 새 checkout 검사(`m0-clean-check.log`, `current-clean-check.log`), 단회 검사(`check-45.log`), 실패를 포함한 반복 검사(`check-45-repeat20.log`), 정적 검사(`static.log`), 실제 교차 다중 연결 원자료(`cross-multiple/`)를 보존했습니다.

이번 환경에는 clang-format 실행 파일이 없어 자동 형식 검사는 다시 수행하지 못했습니다. sanitizer와 물리 리눅스 perf 정확도는 이 초기 완료 범위가 아니었습니다. 당시 아직 하지 않았던 M5의 외부 OpenSSL 명령 연결과 M6 비교는 뒤의 G009·G010 절에서 각각 완료했습니다.

## 같은 날 추가 결정 — 암호군 고정

사용자 결정에 따라 `TLS_AES_128_GCM_SHA256`만 허용하도록 `src/config/config.cpp`, `src/lifecycle/lifecycle.cpp`, `implementations/openssl/adapter.cpp`를 바꿨습니다. `include/turtle/adapter.hpp`의 기본값과 ABI는 유지하고 고정 범위를 주석으로 명시했습니다. 명세의 FR-SCOPE-1·FR-CFG-1, README, 어댑터 지원 문서와 진행 상태도 이 범위에 맞췄습니다. 다른 암호군을 지원하는 작업은 더 이상 미완료 목록이 아닙니다.

`tests/config/config_test.cpp`, `tests/lifecycle/lifecycle_test.cpp`, `tests/adapters/smoke.cpp`에서 명령행·프로필·직접 실행·단독 어댑터의 다른 암호군 및 후보 목록 거절을 확인합니다. 거절은 TLS 입출력 전에 일어나야 합니다. wolfSSL 어댑터는 기존에 설정 오류를 진단 컨텍스트에 담았다가 첫 호출에서 돌려주는 방식이므로, 컨텍스트가 반환됐다는 이유만으로 설정을 받아들였다고 판단하지 않습니다. 새 시험도 이 기존 계약을 존중합니다.

설정 및 OpenSSL 단독 어댑터가 기존 코드에서 다른 암호군을 받아들이는 실패를 먼저 확인했습니다. 수정 후 `REPEAT=1 JOBS=4 scripts/check.sh`의 **45개 시험**, 실제 3×3 TLS 연결, 모듈 검사, cppcheck·clang-tidy, `git diff --check`가 통과했습니다. 기록은 `results/validation-20261015-cipher/check-final.log`와 `static.log`에 있습니다. 이 단회 통과가 앞 절의 인증서 반복 시험에서 관측한 시각 문제를 해결했다는 뜻은 아닙니다. netem은 의견 검토만 했으며 네트워크 설정을 변경하거나 기능을 구현하지 않았습니다.

## 같은 날 Mock CA·netem 작업의 중간 검증

이 절은 진행 중인 작업 트리의 중간 증거입니다. 아래 부품 통과를 실제 TLS+netem 전체 목표 완료로 확대하지 않습니다.

| 자료 | 직접 확인한 범위 |
|---|---|
| `results/mock-ca-goal/g002-build.log` | lookup/config/transport/capability 계약을 생산·시험 빌드에 연결했습니다. |
| `results/mock-ca-goal/g002-verify.log` | `config_profiles_and_overrides`, `transport_normal_bytes`, `capability`, `lookup_contract`, `lookup_real_tcp` 5개 대상을 각각 20회 실행해 모두 통과했습니다. 실제 TCP cold/warm 조회는 입력 원본 PEM 바이트를 사용했습니다. 이 자체는 TLS 인증서 검증 증거가 아닙니다. |
| `results/mock-ca-goal/service-record-verify.log` | `service_record`, `attempt_record`를 각각 20회 실행해 모두 통과했습니다. 자식 서비스 schema와 parent attempt 분모 기록의 단위 증거입니다. |
| `results/mock-ca-goal/after-shared-contracts-and-heap.log` | 공유 계약과 heap tracker 변경 뒤 당시 전체 45개 시험이 단회 통과했고 11개 부품의 정적 include 경계·순환 검사도 통과했습니다. 이후 추가된 lifecycle/netem/보고 변경의 최종 전체 검증은 아닙니다. |

첫 전체 재검사는 `results/mock-ca-goal/g003-full-check-first.log`에 보존했습니다. 55개 중 51개가 통과하고 4개가 실패했으므로 전체 성공 기록이 아닙니다.

- `lookup_openssl_same_library`, `lookup_wolfssl_same_library`, `lookup_mbedtls_same_library`는 서비스 원자료의 `object_id`가 canonical `fnv1a64:...` 문자열로 바뀌었는데 시험이 이전 정수 표현을 기대하여 실패했습니다. 실제 TLS 결과를 포함한 시험이라도 이 계약 불일치를 고치고 다시 통과하기 전에는 세 조회 통합 시험을 성공으로 세지 않습니다.
- `pipeline_mbedtls_wolfssl`은 `turtle-report`가 SIGSEGV로 끝나 실패했습니다. TLS 역할 실행이 앞서 진행됐더라도 보고 단계 실패를 전체 파이프라인 성공으로 바꾸지 않습니다.
- 같은 실행에서 새 `lifecycle_mock_ca_lookup`, `lifecycle_attempt_ledger`, `lookup_report`와 `local_pki_matrix` 단회는 통과했습니다. 단회 PKI 통과는 앞서 실패한 20회 반복의 시각 역행 제한을 해소하지 않습니다.

이 첫 실행의 실패는 뒤에서 수정하고 재검사했습니다. 과거 실패 로그는 삭제하거나 성공으로 바꾸지 않습니다.

### 통합·정적 검사 수정 결과

`results/mock-ca-goal/pre-loss-check.log`에서 경고를 오류로 처리한 소스·시험 빌드, 57/57 시험과 11개 부품 include 경계 검사가 통과했습니다. 세 TLS 라이브러리의 조회 통합 시험과 앞서 SIGSEGV였던 교차 파이프라인도 이 실행에 포함됐습니다.

첫 정적 검사 `results/mock-ca-goal/static-first.log`는 성공이 아닙니다. cppcheck `passedByValue` 2건과 clang analyzer dead store 2건이 있었습니다. 불필요한 값 복사와 두 상태 저장을 제거한 뒤 `results/mock-ca-goal/pre-loss-static.log`에서 외부 소스를 제외한 생산 번역 단위 21개의 cppcheck 2.13.0과 clang-tidy 18.1.3이 통과했습니다.

### PKI 시각 역행 수정

`scripts/make-pki.sh`는 이제 발급 시작 시각을 한 번만 읽고 root·intermediate·leaf 전체에 같은 유효 기간을 사용합니다. `notBefore`는 발급 시각보다 300초 앞, `notAfter`는 발급 시각보다 3,650일 뒤입니다. OpenSSL 3.0에서도 명시적 시작·종료 시각을 지정할 수 있도록 `openssl ca`를 사용하며 정상 `openssl verify`를 유지합니다.

ECDSA P-256·RSA-2048·Ed25519 잎과 체인 길이 1~3의 9조합을 각각 두 번 system OpenSSL 3.0과 고정 OpenSSL 3.5에서 확인했고 모두 통과했습니다. 추가 시험은 `date`가 발급 과정에 돌려주는 시각만 실제 검증 시각보다 240초 앞당겼고 host 시계를 바꾸지 않았습니다. 그 상태에서 만든 인증서도 실제 시각의 정상 검증을 통과했습니다. 이 결과는 이전 `certificate is not yet valid` 원인을 수정했음을 보여 주지만, `results/validation-20261015-resume/check-45-repeat20.log`의 과거 실패 사실을 지우지는 않습니다.

## 고정 Mock CA·netem 실제 검증

N05를 포함한 묶음은 조건을 결과에 맞춰 바꾸거나 loss 조건을 재실행하지 않고 정확히 한 번 수행했습니다. 최종 기준은 `results/mock-ca-goal/netem-verify-final/verification-manifest.json`이며 `status=complete`입니다.

공개 객체는 ECDSA P-256 3인증서 `server-chain.pem`의 원본 1,890바이트, `fnv1a64:58fddee27893d105`였습니다. 조회 응답은 이 원본과 byte-for-byte 비교해 cache insert한 뒤 `USABLE_OBJECT` 이후 stock OpenSSL TLS를 시작했습니다. TLS는 계속 표준 Certificate 메시지와 인증서 검증을 사용합니다. 실제 인증서 압축·생략·캐싱 기법을 구현했다는 증거가 아닙니다.

| 조건 | 결과 | 검증 의미 |
|---|---|---|
| baseline | 8/8 success | qdisc 없는 격리 topology 기준 |
| zero | 8/8 success | 네 방향 netem delay/loss 0 |
| CA→client 20ms | 8/8 success | CA 경로 지연 readback과 흐름 |
| TLS server→client 20ms | 8/8 success | TLS 경로 선택성 |
| CA→client 5ms·20% loss | **64/64 success** | 고정 N05 loss gate |
| CA→client 1000ms, timeout 100ms | 3/3 timeout | timeout 분모와 결측 보존 |
| fixed snapshot warm hit | 1/1 success, request 0 | 준비 TCP와 응용 조회 0건 구별 |

N05의 scenario qdisc drop 차이 합계는 94, 같은 CA 흐름의 `TCP_INFO.total_retrans` 차이 합계는 58입니다. `packets.jsonl`에는 AF_PACKET packet 행 4,148개가 있습니다. 이는 router veth에서 본 skb이며 ingress/egress 중복을 포함할 수 있어 물리 패킷 수나 고유 패킷 수로 해석하지 않습니다.

timeout 원장은 requested=started=timeout=3을 보존하고 missing artifact 9개를 열거했습니다. 끝나지 않은 phase는 partial window와 `:missing` observation ID로 남았습니다. 세 attempt 모두 `secondary_reasons`에 `owned child required SIGKILL after cleanup grace`가 있어 실제 SIGKILL과 소유 자식 reap 경로를 실행했습니다. 250ms는 SIGKILL 뒤 운영체제 회수를 기다리는 **최대 budget**이며 실제 소요 시간을 측정한 값이 아닙니다. N05 loss 64 attempts에는 강제 kill이 없었습니다. wait/reap가 합성 EIO로 끝나 회수를 증명할 수 없는 분기는 통제된 wrapper 시험으로 확인했습니다.

일곱 실행은 모두 network integrity gate를 통과했습니다. host network identity의 전후가 같았고, 소유 observer/helper가 회수됐으며 namespace FD와 pipe FD가 닫혔습니다. MTU 1500 및 여덟 interface의 TSO/GSO/GRO off readback도 요청과 일치했습니다. non-null loss seed는 지원되지 않는 조건으로 명시적으로 거절됐습니다.

## 최종 G005 오프라인 보고

N05를 다시 실행하지 않고 보존한 일곱 조건의 원자료를 최신 빌드로 다시 해석·요약했습니다.

- `results/mock-ca-goal/netem-final-reports.log`: 조건별 보고서와 합산 보고서 생성을 확인합니다.
- `results/mock-ca-goal/netem-verify-final/report-final/lookup-summary.json`: requested=started=100, success=97, timeout=3, attempt table 100행, connection table 100행, joined rows 100행입니다. 각 조건은 자기 분모를 유지합니다.
- 성공한 network attempt는 setup/scenario/cleanup begin/end의 정확히 여섯 observation 참조, host unchanged와 owned cleanup이 모두 확인돼야 비교 적격입니다. timeout 3건은 자동 비교와 성공 분포에서 제외됩니다.
- malformed ledger, 누락된 참조, host 변경이나 cleanup 실패는 fail closed입니다. loopback metric은 설명용으로 보존하지만 network comparison eligibility와 분리합니다.
- `results/mock-ca-goal/netem-interpret-final.log`: 유효 TLS 역할 파일 194개를 모두 해독했습니다. timeout에서 missing/invalid인 역할 파일 6개는 결측으로 보존하고 성공으로 승격하지 않았습니다.
- `results/mock-ca-goal/netem-verify-final/latency-diagnostics.json`: 조건별 remote lookup 중앙값은 모두 `diagnostic_only`입니다. latency 임계값으로 gate를 판정하지 않았고 성능 논문 주장으로 사용하지 않습니다.

G005의 구현·고정 실행·보고를 완료했습니다.

## G006 최종 검증

| 증거 | 결과 |
|---|---|
| `results/mock-ca-goal/final-repeat20.log` | 경고를 오류로 처리한 빌드에서 57개 시험을 각각 20회, 총 **1,140회** 실행해 실패 0건으로 통과했습니다. 11개 부품 include 경계 검사도 통과했습니다. |
| `results/mock-ca-goal/final-static.log` | 외부 소스를 제외한 생산 번역 단위 21개의 cppcheck·clang-tidy가 통과했습니다. |
| `results/mock-ca-goal/report-recompute.log` | 보존 원자료에서 다시 만든 `summary.json`과 `lookup-summary.json`이 각각 최종 파일과 정확히 같은 JSON임을 확인했습니다. |
| `results/mock-ca-goal/netem-verify-final/verification-manifest.json` | N05를 한 번만 실행한 기존 증거가 그대로 유지됐습니다. qdisc drop 94, CA 재전송 58, aggregate 100/97/3과 최신 network-integrity 규칙을 보존합니다. |
| 독립 최종 검토 | native code review는 APPROVE, 지적 0건이었고 architecture review는 CLEAR로 모든 invariant를 확인해 추가 수리가 없었습니다. |
| bounded cleanup 최종 감사 | 남아 있던 fallback escalation을 모두 확인했고 제품 코드 수정이 필요한 항목은 없었습니다. |

G001~G006의 요구 증거를 모두 확인해 검증 완료로 표시합니다. 실제 인증서 생략·압축·캐싱 기법, ACME/OCSP, 스택·NIC 계측, 물리 Linux perf 정확도와 성능 결론은 이 완료 범위에 포함하지 않습니다. `latency-diagnostics.json`을 포함한 데이터 유래 가설은 진단용이며 출판 성능 주장으로 승격하지 않습니다.

## G007 순수 TLS netem 후속 검증

`tests/integration/pure_tls_netem.py`는 `lookup.enabled=false`인 stock OpenSSL TLS에 대해 다음 계약을 검사하도록 추가했습니다.

- client/server/router 세 namespace, 두 veth 링크, `tls_c2s`·`tls_s2c` 두 qdisc만 만듭니다.
- CA namespace·FD·주소·interface·participant와 `ca.jsonl`, `lookup.jsonl`, `lookup-summary.json`, snapshot/object 결과를 만들지 않습니다.
- 양방향 0ms와 20ms, loss 0을 각각 2 attempts 실행하고 네 attempt 모두 TLS 1.3 전체 핸드셰이크, Certificate, Finished, 암호화된 핑퐁과 양방향 stream 대응을 요구합니다.
- setup/scenario/cleanup의 여섯 observation, host unchanged, helper 회수, namespace/pipe FD 닫힘을 attempt마다 확인합니다.
- 합산 `summary.json`은 네 그룹 `(0ms, client)`, `(0ms, server)`, `(20ms, client)`, `(20ms, server)`을 유지하고 각 그룹에 measured `elapsed_ns`와 `thread_cpu_ns` 두 값이 있어야 합니다.
- 요청·실제 network policy는 안정 그룹 identity에 들어가고 runtime integrity 결과는 identity 밖의 표본 metadata와 그룹 적격성에 남아야 합니다.

실제 순수 TLS 경로 자체의 증거는 `results/followup-tls-netem/pure-tls-preserved/`에 보존했습니다. 0ms·20ms 원자료는 각각 requested=started=success=2여서 모두 4 attempts·8개 역할 파일이었고 CA·lookup 결과가 없었습니다. 동결한 shared strict parser를 쓰는 최신 reporter로 같은 원자료에서 보고서를 두 번 다시 만들었으며 두 `summary.json`은 byte-for-byte와 JSON 구조가 모두 같고 이전 두 출력과도 같았습니다. 공통 SHA-256은 `1ee2de21b2557d07c88b4d0d61333aa8e18bd675f989862ffcf6879ca4a86bed`입니다. 각 보고서는 invalid sample 0, 표본 행 8개, 위 네 조건·역할 그룹을 보존했고 각 그룹의 `elapsed_ns`·`thread_cpu_ns` count는 2였습니다. `lookup-summary.json`은 생성되지 않았습니다. `validation-summary.json`과 `validation.log`, 원자료 hash manifest가 이 확인을 남깁니다.

그러나 `results/followup-tls-netem/check-second.log`의 전체 실행은 **57/58 통과**였습니다. 새 `pure_tls_netem_actual`, 일반 report·lookup report와 TLS pipeline은 통과했지만 `netem_runner_contracts`가 시작 중 `[Errno 19] No such device`로 실패했습니다. 이 실패 기록은 삭제하거나 전체 성공으로 바꾸지 않습니다.

원인은 namespace helper를 만든 뒤 고정 30ms만 기다리고 `/proc/<pid>/ns/net`을 열던 시작 race였습니다. 동시 재현에서 같은 ENODEV를 확인한 뒤, helper가 `unshare`와 진입을 끝냈음을 bounded readiness pipe로 알리도록 바꿨습니다. 수리 뒤 첫 bounded contract 반복은 16/16 통과했습니다. 이어서 `results/followup-tls-netem/netem-startup-repeat20.log`에서 `local_test_certificates`, `netem_runner_contracts`, `pure_tls_netem_actual`을 각각 20회 실행해 모두 통과했습니다.

동결한 최종 소스의 증거는 다음과 같습니다.

| 증거 | 결과 |
|---|---|
| `results/followup-tls-netem/check-final-repeat20.log` | 경고를 오류로 처리한 소스·시험 빌드 뒤 58개 시험을 각각 20회, 총 **1,160회** 실행해 실패 0건으로 통과했습니다. 11개 부품 include 경계·순환 검사도 통과했습니다. |
| `results/followup-tls-netem/static-final.log` | 외부 소스를 제외한 생산 번역 단위 24개의 cppcheck·clang-tidy가 통과했습니다. |
| `results/followup-tls-netem/pure-tls-preserved/validation-summary.json` | 4 attempts·8개 역할 파일·네 조건/역할 그룹, CA/lookup 결과 부재, 최신 두 보고서와 이전 보고서의 동일성을 확인합니다. 보존 작업은 네트워크 실행이나 N05를 수행하지 않았습니다. |
| 독립 검토 | 수명주기 책임 분리와 shared strict ledger reader가 모두 지적 없이 승인됐습니다. grouping·integrity·준비/측정 소켓 identity 검토에도 추가 문제가 없었습니다. |

이 증거로 G007의 현재 범위를 검증 완료로 표시합니다. G006의 57×20=1,140회 성공과 G007의 58×20=1,160회 성공은 서로 다른 시점의 증거이며 합치거나 대체하지 않습니다.

M13·M14의 N05는 이 후속 검증 때문에 다시 실행하지 않습니다. 기존 64/64 성공, qdisc drop 94, CA 재전송 58은 정확히 한 번 실행한 고정 증거이며 loss 조건 확대도 하지 않습니다. G007 종료 시점에는 M5의 수정하지 않은 OpenSSL 명령행 양방향 연결, M6, M7 관측자 비교가 다음 단계였습니다.

## G008 두 커밋 cutover

G007 동결 뒤 작업 트리의 139개 경로를 책임과 검증 경계에 따라 두 커밋으로 나눴습니다. cutover 시점에는 추적할 제품·시험·문서 변경이 모두 두 커밋에 들어갔고 Git 작업 트리가 깨끗했습니다. 현재 보이는 시험 CMake 변경은 그 뒤 시작한 M5 작업이며 G008 누락이 아닙니다.

| 커밋 | 범위와 독립 증거 |
|---|---|
| `cd2a5fa` | M0~M4 기반 계약을 고정했습니다. 격리한 후보에서 45개 시험을 각각 20회, 총 900회 통과했고 10개 부품 경계 검사를 통과했습니다. 이 커밋에는 정적 검사를 다시 실행하지 않았다는 `Not-tested` trailer를 그대로 남겼습니다. |
| `3723056` | lookup·Mock CA·attempt 원장·netem·G007을 추가했습니다. 새로 동결한 최종 트리에서 58개 시험을 각각 20회, 총 1,160회 통과했고 11개 부품 경계 검사와 생산 번역 단위 24개의 cppcheck·clang-tidy가 통과했습니다. N05는 다시 실행하지 않았습니다. |

두 커밋은 이유를 첫 줄에 쓰고 `Constraint`, `Rejected`, `Confidence`, `Scope-risk`, `Reversibility`, `Directive`, `Tested`, `Not-tested`를 필요한 범위에서 기록한 Lore 형식을 따릅니다. `/build*`, `/results/`, `/.deps/`, `/pki/`, `/.omx/` 같은 기존 실행 산출물에 더해 `/.omc/`, `/.omx-state-locks/`, `/.omx-state-locks.identity.json`을 무시해 런타임 상태를 제품 이력과 분리했습니다. 이 규칙은 증거를 삭제한다는 뜻이 아니라 결과 폴더와 커밋의 `Tested` trailer에서 검증 근거를 보존한다는 뜻입니다.

G008을 완료로 표시합니다. 이 cutover 자체는 M5 외부 CLI 상호운용성, M6 native/callback 비교, M7 관측자 영향 검증의 성공 증거가 아닙니다. G008 cutover 시점에는 M5의 12조건을 아직 구현 중이었으며, 그 뒤의 완료 증거는 다음 절에 따로 기록합니다. M6·M7 계획은 승인됐지만 실행은 미뤘습니다.

## G009/M5 수정하지 않은 OpenSSL CLI 최종 검증

첫 구현은 활성 세 어댑터×client/server×서버 인증/상호 인증의 12개 CTest를 등록했고 실제 TLS 연결과 양방향 응용 바이트 교환까지 실행했습니다. 그러나 전체 70개 시험의 첫 반복 뒤 증거 감사를 하면서 Mbed TLS의 `api.name()` 값 `Mbed TLS`를 내부 분류 문자열 `mbedtls`와 대응하지 못한 문제를 찾았습니다. 그 결과 Mbed TLS의 group·signature·resumed·HelloRetryRequest 근거가 `unobserved`로 잘못 기록되고, 추론값의 선언 일관성 assertion도 실행되지 않았습니다.

이 중간 원자료는 `results/m5-cli/preserved/`에 보존했습니다. `complete-runs/`의 12조건 모두 실제 TLS 1.3·AES-128-GCM, 기대한 서버/상호 인증, 양방향 응용 바이트, 실제 `/usr/bin/openssl`의 version/help/argv, 양쪽 프로세스 exit 0과 reap, timeout 없음과 빈 cleanup을 확인합니다. `selection.json`과 세 hash manifest는 선택한 36개 파일의 복사 전후 동일성을, `validation-summary.json`과 `validation.log`는 감사 결과를 남깁니다. 다만 Mbed TLS 네 조건의 잘못된 근거 분류 때문에 `all_negotiation_metadata_criteria_pass=false`입니다.

이 첫 반복과 당시 정적 검사 결과는 최종 M5 증거가 아닙니다. 어댑터 표시 이름을 명시적인 근거 category에 대응시키고 각 category의 expected source를 회귀 시험하도록 수리했습니다. 수정하지 않은 CLI와 실제 TLS 교환이 성공했다는 사실만으로 metadata 계약의 누락을 덮지 않았으며, 아래의 새 12조건 원자료·전체 반복·정적 검사·독립 검토를 모두 완료 기준으로 사용했습니다. N05·netem·lookup은 이 작업에서 실행하지 않았습니다.

수리한 구동기의 새 12조건 원자료 감사는 통과했습니다. `results/m5-cli/preserved/final-complete-runs/`에 조건별 세 파일, 모두 36개를 보존했고 `final-selection.json`, `final-selected-source-paths.txt`, 세 `final-*.sha256` manifest가 복사 전후 동일성을 확인합니다. `final-validation-summary.json`과 `final-validation.log`는 앞서 확인한 실행·인증·응용 바이트·프로세스·CLI provenance와 함께 협상 근거 표도 검사합니다. Mbed TLS 네 조건의 group·signature·resumed·HelloRetryRequest는 이제 모두 `inferred`이며 근거는 고정 configuration에 따른 추론이고 runtime query가 없다는 설명입니다. 이전 partial 원자료를 새 증거로 바꾸지 않고 별도 보존합니다.

이 12조건 감사 자체의 `overall_g009_completion_claimed`는 의도대로 false입니다. 원자료 감사 한 가지가 전체 회귀·정적 검사와 독립 검토를 대신하지 않기 때문입니다.

동결한 수리 코드의 최종 증거는 다음과 같습니다.

| 증거 | 결과 |
|---|---|
| `results/m5-cli/check-final-repeat20.log` | 경고를 오류로 처리한 소스·시험 빌드 뒤 70개 시험을 각각 20회, 총 **1,400회** 실행해 실패 0건으로 통과했습니다. 12개 CLI 조건도 각각 20회여서 모두 240회이며, 11개 부품 include 경계·순환 검사도 통과했습니다. |
| `results/m5-cli/static-final.log` | 생산 번역 단위 24개의 cppcheck·clang-tidy가 통과했고 새 `tests/adapters/cli_endpoint.cpp`의 별도 clang-tidy도 exit 0이었습니다. |
| `results/m5-cli/preserved/final-validation-summary.json` | 세 어댑터×두 역할×두 인증 방식의 12조건에서 실행·인증·응용 바이트·프로세스·CLI provenance와 협상 근거 표를 모두 통과했습니다. 36개 보존 파일의 hash도 일치했습니다. |
| 독립 검토 | metadata/assertion 수리 뒤 코드를 승인했고, 최종 12조건 원자료를 다시 읽은 검토도 지적 없이 승인했습니다. |

시험에 사용한 수정하지 않은 CLI는 `/usr/bin/openssl`의 OpenSSL 3.0.13입니다. 상대 어댑터는 OpenSSL 3.5.4, wolfSSL 5.8.2, Mbed TLS 3.6.4이며 모두 callback I/O를 사용했습니다. 각 조건은 TLS 1.3·`TLS_AES_128_GCM_SHA256`, 기대한 peer 인증서와 서버/상호 인증 결과, 두 방향의 고정 응용 문자열, 양쪽 exit 0과 reap, timeout 없음과 cleanup 신호 부재를 확인했습니다.

협상 결과의 출처는 분리해서 기록합니다. 모든 어댑터의 version·cipher·peer certificate는 runtime 관측입니다. OpenSSL의 group·resumed·HelloRetryRequest는 관측하고 signature는 관측하지 못합니다. wolfSSL의 group·signature·resumed는 관측하고 HelloRetryRequest는 단일 허용 group에서 추론합니다. Mbed TLS의 group·signature·resumed·HelloRetryRequest는 고정 configuration에서 추론하며 runtime query라고 부르지 않습니다.

공개 adapter v1에는 TLS `close_notify`를 구동하는 함수가 없습니다. 따라서 시험은 응용 교환 성공 뒤 connection을 닫고 CLI에 `-ignore_unexpected_eof`를 명시합니다. 이는 EOF 계약을 맞춘 것이며 정상 TLS shutdown alert를 검증했다는 뜻이 아닙니다. 이 시험은 WSL의 기능 상호운용성 근거이지 native/callback 동등성, 관측자 비용이나 성능 결론도 아닙니다.

이 결합 증거로 G009/M5의 현재 범위를 완료로 표시합니다. N05·netem·lookup은 실행하지 않았습니다. G009 완료 시점에는 M6·M7이 승인된 별도 계획뿐이었으며, 이후 M6 결과는 다음 절에 기록합니다.

## G010/M6 OpenSSL callback/native I/O 경로 최종 검증

동결한 구현은 OpenSSL↔OpenSSL callback/native×서버 인증/상호 인증 네 정상 조건을 실제 `turtle run`으로 실행합니다. 모든 조건은 새 context·연결, TLS 1.3, `TLS_AES_128_GCM_SHA256`, P-256 요청, tickets 0, 32바이트 암호화 핑퐁, 역할별 인증 결과와 attempt 성공을 요구합니다. wolfSSL·Mbed TLS의 native 경로는 지원하지 않으며 시험 범위를 줄여 성공으로 세지 않습니다.

원자료·해석·보고 회귀는 다음 경계를 고정합니다.

- callback의 TLS stream/I/O와 설정 가능한 kernel receive 수집 경로는 available입니다. kernel receive availability만으로 실제 timestamp 사건 발생을 주장하지 않습니다.
- native의 stream·I/O·kernel receive는 `native_socket_io_not_observed`입니다. 빈 stream 해석은 `decryption_complete=false`이며 과거 library-only 자료도 legacy unavailable로 읽습니다.
- native client는 호출 경과·스레드 CPU를 보존하되 I/O 분해와 stream byte metric은 `null`입니다. native server의 주 구간은 `server_first_receive_not_observed`이고 elapsed·CPU도 없습니다.
- 기능 성공과 metric availability를 분리하고 native 그룹을 자동 비교에서 제외합니다.

별도 실제 외부 조건은 기존 pure TLS zero-loss runner에 callback/native를 각각 2 attempts로 실행합니다. 수신자 쪽 router egress AF_PACKET 행의 양방향 payload를 확인하고 skb count·payload 합을 근사 observer-read-time 창별로 보존하되, 두 모드 수치의 동일성은 요구하지 않습니다. 이는 full pcap·syscall·물리 wire나 고유 TLS byte 증거가 아닙니다. `verify`와 N05는 실행하지 않았고 M13·M14 범위를 확장하지 않았습니다.

동결 트리의 실행 증거는 다음과 같습니다.

| 증거 | 결과 |
|---|---|
| `results/io-path/check-final-repeat20.log` | 경고를 오류로 처리한 소스·시험 빌드 뒤 72개 시험을 각각 20회, 총 **1,440회** 실행해 실패 0건으로 통과했습니다. `io_path_normal`과 지원 환경의 `io_path_external_metadata`도 각각 20회 모두 실제 통과해 skip이 없었고, 11개 부품 include 경계·순환 검사도 통과했습니다. 로그 SHA-256은 `ec865445da3ede7380623c53667ef1f3922984acecd0c83f8b47347246488233`입니다. |
| `results/io-path/static-final.log` | 외부 소스를 제외한 생산 번역 단위 24개의 cppcheck·clang-tidy가 통과했습니다. |
| 독립 검토 | 제품 코드 review는 APPROVE, 구조 검토는 CLEAR였고 추가 수정 요구가 없었습니다. |

보존한 실제 원자료의 독립 감사도 통과했습니다.

| 증거 | 결과 |
|---|---|
| `results/io-path/preserved/validation-summary.json` | normal 4조건은 4 attempts·8개 역할 파일 모두 성공했습니다. callback은 stream 해독까지 완료했고 native는 명시적으로 unavailable이었습니다. native client의 elapsed·CPU와 native server의 unavailable 주 구간도 원자료와 보고서가 일치했습니다. |
| 같은 파일의 external 감사 | callback/native 두 모드가 각각 2/2 attempts 성공해 모두 4 attempts·8개 역할 파일입니다. 각 모드의 12개 phase observation, host unchanged, helper/FD cleanup과 양방향 receiver-facing egress payload를 확인했습니다. |
| `results/io-path/preserved/validation.log` 및 hash manifest | 선택한 171개 파일의 원본·보존본 hash가 세 manifest에서 일치했고, `derived/`의 최신 offline report도 정규화한 기존 보고서와 같았습니다. |

normal callback 원자료에서 `raw_timestamp_ns`가 실제로 있는 사건은 서버 인증 client/server가 각각 14/8개, 상호 인증 client/server가 16/12개였습니다. 이 행들이 해당 실행의 kernel receive 사건 증거입니다. `kernel_receive_events.available=true`만으로 이 발생 횟수를 대신 주장하지 않습니다. native 원자료는 해당 수집 경로 자체를 unavailable로 기록합니다.

외부 표에서 callback은 c2s 6 skb/688 payload bytes, s2c 4/2,601이었고 native는 c2s 6/688, s2c 4/2,599였습니다. 양쪽 capture footer는 두 interface 모두 packets 31, drops 0이었습니다. 이 숫자는 receiver-facing router egress에서 사용자 공간 observer가 읽은 skb metadata의 기술값입니다. timestamp와 scenario 창은 observer/decode read time 기반 근사값이며, skb 수는 물리 packet·고유 TLS record 수가 아니고 payload 합은 재전송·분할을 제거한 unique TLS bytes가 아닙니다. 두 모드 수치의 일치도 합격 조건이 아닙니다.

72×20 실행·정적 검사·독립 검토와 이 원자료 감사를 결합해 G010/M6의 제한된 범위를 완료로 표시합니다. 이는 기능·관측 경계 검증이며 WSL 성능 결론, callback/native 동등성, full pcap·syscall·물리 wire 증거가 아닙니다. M6 완료 시점에는 M7의 `channel_observer` flag와 공통 `handshake_call_begin_to_application_complete` 구간이 다음 단계였습니다.

## G011/M7 채널 관측자 on/off 최종 검증

동결 구현은 `measurement.channel_observer`를 JSON-only 내부 설정으로 추가했고 기본값과 과거 필드 부재를 true로 유지합니다. false는 Channel 관측 함수 포인터만 비우며 callback transport, actual socket buffer와 timestamp 설정, CALL/WAIT, keylog/plaintext, perf·calibration을 유지합니다. off의 stream·I/O·kernel receive availability는 `channel_observer_disabled`이고 빈 stream을 0바이트 해독 성공으로 처리하지 않습니다.

보고서는 client/server, observer on/off 모두에 `handshake_call_begin_to_application_complete`를 직접 원자료에서 재계산합니다. 첫 handshake CALL_BEGIN에서 client app_recv 또는 server app_send의 전체 32바이트를 완료한 마지막 성공 CALL_END까지이며 event sequence와 elapsed를 보존합니다. CPU snapshot은 elapsed와 독립이므로 누락·역행이면 CPU만 이유 있는 `null`입니다. observer-off server의 기존 first-receive primary가 unavailable인 사실은 그대로이고, 새 공통 metric이 이를 대체하지 않습니다. native server도 같은 CALL 사건이 있으면 이 공통 metric을 가질 수 있습니다.

첫 실제 통합 실행은 attempt 원장에 존재하지 않는 batch 필드를 요구해 실패했고 `results/observer-impact/check-first.log`와 `normal-1792048076611007990-1085316`에 보존했습니다. 다음 실행은 raw `config.tls`에 직렬화되지 않는 version을 요구해 실패했으며 `results/observer-impact/batch-recheck.log`와 `normal-1792048376493542567-1092327`에 남겼습니다. 제품 schema를 시험 기대에 맞춰 늘리지 않고 batch는 역할 raw config에서, TLS 조건은 실제 직렬화 필드에서 확인하도록 고쳤습니다.

수정 뒤 `results/observer-impact/batch-final.log`의 실제 OpenSSL callback 실행은 on/off, off/on, on/off, off/on 순서의 4 batches를 통과했습니다. 각 위치는 samples 2여서 모두 16 attempts·32개 역할 파일이고, 각 모드는 역할별 8개 공통 elapsed·CPU 값을 남깁니다. `diagnostic-summary.json`은 역할별 raw 값과 on-minus-off 산술 차이를 보존하지만 부호·크기·0·통계적 유의성은 합격 기준이 아닙니다. 이 WSL 기능 표본으로 순위나 성능 결론을 내리지 않습니다.

두 profile을 정규화하면 다른 입력 변수는 `measurement.channel_observer` 하나뿐입니다. 실행 argv의 차이도 대응하는 profile·batch·output 식별자에 한정됩니다. 32개 역할 파일은 같은 framework/OpenSSL 판, callback I/O, 실제 socket buffer·kernel timestamp readback, perf 설정, keylog/plaintext와 buffer 크기를 보존했습니다. 모든 TLS 인증·응용 교환은 성공했고 on은 stream 해독 완료, off는 stream·I/O·KERNEL_RX unavailable과 빈 stream 비해독을 확인했습니다.

동결 트리의 최종 결합 증거는 다음과 같습니다.

| 증거 | 결과 |
|---|---|
| `results/observer-impact/check-final-repeat20.log` | 경고를 오류로 처리한 소스·시험 빌드 뒤 73개 시험을 각각 20회, 총 **1,460회** 실행해 실패·skip 없이 통과했습니다. `observer_impact_normal`도 20회 통과했고 11개 부품 include 경계·순환 검사도 통과했습니다. 로그 SHA-256은 `6b147a819d17b1368ab1f22a62534ea6495891878ad7c86fd6de0a5eb4168021`입니다. |
| `results/observer-impact/static-final.log` | 외부 소스를 제외한 생산 번역 단위 24개의 cppcheck·clang-tidy가 통과했습니다. |
| `results/observer-impact/preserved/validation-summary.json` | 선택한 성공 실행의 294개 파일·1,697,930바이트가 세 hash manifest에서 같았습니다. 16/16 attempts, 32개 역할 파일과 네 역할×observer 보고 그룹, 모든 공통 경계의 raw 재계산과 offline report 동일성을 확인했습니다. |
| 독립 검토 | 제품 code review는 APPROVE, 구조 검토는 CLEAR였고 추가 제품 수정 요구가 없었습니다. |

보존 감사에서 실패한 두 sibling 실행은 명시적으로 제외하고 위의 `normal-1792048590965177294-1097154`만 선택했습니다. 실제 성공 실행에는 CPU snapshot 누락이 0건이었습니다. elapsed가 유효하지만 CPU가 누락·역행할 때 CPU만 `null`로 두는 경계는 unit test 증거이며 실제 실행에서 관측한 결측이라고 주장하지 않습니다.

raw에서 다시 계산한 on-minus-off 단순 산술 평균은 client elapsed 42,009.375ns·CPU 49,291.625ns, server elapsed 43,627.0ns·CPU 6,911.125ns였습니다. 이 값은 구현된 진단 계산이 원자료와 맞는지 확인하는 자료일 뿐입니다. 효과의 방향·부호·0 여부·크기·유의성, WSL 순위, uninstrumented 기준이나 완전한 관측 비용 보정으로 해석하지 않습니다.

73×20 실행·정적 검사·독립 검토와 원자료 감사를 결합해 G011/M7의 제한된 범위를 완료로 표시합니다. M13·M14와 N05는 실행하거나 확장하지 않았습니다. G011 완료 시점에는 G012 최종 cleaner·독립 검토와 milestone commit이 다음 단계였습니다.

## G012 최종 QA와 G013 shared network integrity 수리

첫 최종 구조 검토에서 일반 pure TLS 보고가 성공 attempt의 여섯 phase ID 존재만 확인하고, 참조된 observation의 qdisc·trace 본문 완전성을 lookup 보고만큼 엄격하게 요구하지 않는 문제를 찾았습니다. 이 시점의 73×20·정적 검사 결과는 G013 수리 전 과거 증거로 이름을 바꿔 보존했으며 최종 트리 증거로 승격하지 않습니다.

shared network 판독기는 이제 성공 attempt의 여섯 참조 각각에 비어 있지 않은 `qdiscs`를 요구하고, trace 요청이 true이면 non-null `packet_trace`도 요구합니다. 누락·빈 qdisc와 누락·null trace fixture는 condition identity가 같아도 integrity 실패, 빈 metric, 자동 비교 부적격과 comparison 없음으로 끝나야 합니다. 제품 code review는 APPROVE, 구조 재검토는 CLEAR였고 runner나 N05는 실행·수정하지 않았습니다.

보존 원자료 다섯 묶음을 offline으로 다시 보고한 첫 감사는 `results/final-followup/offline/pre-null-compat-validation.json`에 실패로 남겼습니다. pure TLS, M6 normal/external, M7과 실제 630개 성공 phase 참조 본문은 통과했지만, N05 baseline의 qdisc-none/noqueue path가 `limit_packets:null`을 명시한 것을 numeric 누락으로 오판해 성공 8 attempts의 16개 역할 표본을 비교 부적격으로 만들었습니다. 이 실패를 삭제하거나 전체 성공으로 바꾸지 않습니다.

호환 수리는 요청·실제 qdisc가 모두 `none`, actual kind가 `noqueue`, field가 존재하고 null인 경우만 not-applicable로 허용합니다. field 누락이나 netem의 null limit는 계속 실패합니다. 이 좁은 수정과 observer marker-only identity 수정은 correctness 작업이며 NOOP cleanup과 분리합니다.

모든 수리 뒤 동결한 최종 트리의 증거는 다음과 같습니다.

| 증거 | 결과 |
|---|---|
| `results/final-followup/check-repeat20.log` | 경고를 오류로 처리한 소스·시험 빌드 뒤 73개 시험을 각각 20회, 총 **1,460회** 실행해 실패·skip 없이 통과했습니다. 세 실제 어댑터, observer batch와 11개 부품 include 경계·순환 검사도 포함합니다. SHA-256은 `a00cab17c52400ed36e56b7568219fadc2274e3214415529ecceeaf274947ea6`입니다. |
| `results/final-followup/static.log` | 생산 번역 단위 24개의 cppcheck·clang-tidy와 CLI endpoint 전용 clang-tidy가 exit 0이었습니다. SHA-256은 `7891cabf2a42e7d18e191f3594b34853ea8546fe73fd70db5be8ce4c3e0e8189`입니다. |
| `results/final-followup/offline/validation-summary.json` | 다섯 보존 원자료 묶음의 pass 3/4 보고가 각각 결정적으로 같고 입력 hash가 전후 일치했습니다. SHA-256은 `d496965ad67366508d0a9e617dc31baf3442b336a3ad45fb4bb32df45bb7acf6`입니다. |
| 독립 최종 검토 | source code review는 APPROVE, 구조 검토는 CLEAR, bounded cleaner는 NOOP PASS였고 추가 제품 수정 요구가 없었습니다. |

offline 최종 감사는 pure TLS 8개 역할·4그룹, M6 native availability, M7 32개 역할·4그룹과 공통 경계 값을 보존했습니다. 성공한 network attempt의 phase 참조 630/630개가 qdisc·필요 trace 본문을 갖췄습니다. N05는 다시 실행하지 않고 기존 일곱 조건, loss 64 성공, qdisc drop 94, CA 재전송 58, packet 행 4,148개와 requested/started/success/timeout=100/100/97/3을 그대로 확인했습니다. baseline 16개 역할을 포함한 성공 역할 194/194개가 비교 적격이고 timeout 세 표본은 여전히 invalid이며 connection·group으로 승격되지 않았습니다. none/noqueue `limit_packets:null`은 0으로 바꾸지 않고 명시적 not-applicable로 남았습니다.

수리 전 전체 반복·정적 검사 로그는 `check-before-phase-completeness-repeat20.log`, `static-before-phase-completeness.log`, `check-before-noqueue-compat-repeat20.log`, `static-before-noqueue-compat.log`로 이름을 바꿔 최종 증거와 구별했습니다. G008의 두 독립 커밋 증거도 `results/final-followup/commit-proof/`에 복사해 45×20 기반과 58×20 후속 경계를 보존했습니다. 사용자 제공 PDF와 `Zone.Identifier`는 읽거나 수정하지 않았고 계속 untracked 상태입니다.

이 결합 증거로 bounded G012/G013 최종 검증과 현재 사용자 후속 요구, M5·M6·M7 범위를 완료로 표시합니다. 문서 동결 뒤 milestone commit과 goal metadata 정리는 리더가 수행합니다. M10의 eBPF/완전한 계측 정확도 대조와 M12의 실제 인증서 압축·생략·캐싱 기법·원 논문 재현은 구현하지 않은 미래 범위이며 이번 완료 주장에 포함하지 않습니다.

## D1 키 공유 경계의 수정 전후 검증

D1을 바꾸기 전 `ab7099b8382a2bd237f856a9bbeb8f601e6a870b`에서 세 라이브러리의 자기 연결을 각각 한 번 실행했습니다. 모두 `examples/profiles/server-auth.json`, `pki/default`, 고정하지 않은 CPU, 측정 연결 하나, 준비 연결 0개였으며 조회·모의 인증 기관·격리 네트워크는 사용하지 않았습니다.

`results/review-20261015/G002/before/timeline.json`과 `README.md`는 열기, 첫 핸드셰이크 호출에서 첫 전송 시작, 서버의 첫 성공 수신에서 첫 전송 시작 경계를 보존합니다. 열기 경과 시간은 클라이언트/서버 순으로 OpenSSL 25,748/20,791나노초, wolfSSL 315,261/296,166나노초, Mbed TLS 13,025/17,506나노초였습니다. 이 값은 WSL의 단일 표본 구조 진단이며 라이브러리 성능 비교가 아닙니다. 시간 크기만으로 wolfSSL의 열기 작업이 키 생성임을 판정하지 않습니다.

복호화한 바이트를 직접 해석한 결과, 세 연결 모두 ClientHello와 ServerHello가 각각 하나였습니다. ServerHello의 임의값은 HelloRetryRequest 고정값이 아니었고, 양쪽 `key_share`는 P-256 그룹 `0x0017`의 65바이트 비압축 점이었습니다. 이 근거는 어댑터의 HelloRetryRequest 선언값에만 의존하지 않습니다.

수정 전 캡처 자체의 검증은 `results/review-20261015/G002/before/validation/validation.json`에서 통과했습니다. 단회 `scripts/check.sh`는 73/73 시험과 11개 부품 포함 경계 검사를 통과했고, 전체 산출물 대응표 `artifact-manifest.sha256`의 SHA-256은 `df070afae31b62ab309c384d9b2cfb2e68328ccbf652feee1bc9d2651a681189`입니다. 개별 CTest 실행 파일의 해시는 구현 인계 전에 따로 보존하지 못했습니다.


### 수정 뒤 직접 확인

수정 뒤에도 같은 프로필·자격 증명·표본 수·사건 정의로 세 라이브러리의 자기 연결을 다시 실행했습니다. `results/review-20261015/G002/after/provenance.json`의 클라이언트와 서버 여섯 역할은 모두 TLS 1.3 전체 핸드셰이크, 서버 인증, 응용 데이터 왕복을 마쳤습니다. 여섯 원자료의 `measurement_contract_revision`은 모두 1이고, 보고서의 여섯 그룹은 자기·상대 개정값 1을 보존했으며 무효 표본은 없었습니다.

`after/wire-validation.json`은 세 연결의 실제 Hello 바이트에서 ClientHello·ServerHello 각각 하나, P-256 키 공유 하나, HelloRetryRequest 고정 임의값 부재, 양쪽 `pre_shared_key` 확장 부재를 확인했습니다. 어댑터 상태 선언은 보조 근거로만 사용했습니다. 같은 검사를 적용한 세 어댑터의 3×3 실제 연결도 `transcript-tests/full-handshake-matrix.log`에서 통과했습니다.

wolfSSL 어댑터 소스에서 `open()`의 `wolfSSL_UseKeyShare`가 사라졌고, 설정은 `wolfSSL_CTX_set_groups`로 P-256 그룹 목록만 고정합니다. 고정한 wolfSSL 5.8.2 소스의 정상 비-PSK 서버 경로는 `tls13.c:7124-7132` 의 `MatchSuite`에서 `internal.c:37661-37666` 의 `TLSX_KeyShare_Setup`을 거쳐 `tls.c:11211-11224` 의 `TLSX_KeyShare_GenKey`로 이어집니다. 이 경로는 ClientHello 처리 안에 있으므로 서버 키 생성은 첫 성공 수신 뒤입니다. PSK 분기인 `Establish`만을 정상 경로의 근거로 삼지 않았습니다. 이 근거는 호출 경로의 위치를 확인하지만 스칼라 생성의 개별 명령 위치나 내부 비용을 계측한 것은 아닙니다.

수정 전·후에 동일한 추출기를 사용한 `after/before-after-diagnostic.json`에서 wolfSSL 열기 경과 시간은 클라이언트 315,261→19,406나노초, 서버 296,166→12,721나노초였습니다. 클라이언트의 첫 핸드셰이크 호출→첫 전송은 13,621→328,403나노초, 서버의 첫 성공 수신→첫 전송은 17,706→306,513나노초였습니다. 이 한 번의 WSL 값은 작업 형태가 열기에서 핸드셰이크 쪽으로 옮겨갔다는 구조 진단일 뿐입니다. 시간 임계값을 통과 조건으로 쓰지 않았고, 성능 향상이나 라이브러리 순위를 주장하지 않습니다.

최종 검증 근거는 `results/review-20261015/G002/validation/validation-summary.json`에 모았습니다. 이 파일의 SHA-256은 `0bd57cf1d610335623d8b849ae8ee1762c324872b8f5bd6b76315db8e95976d4`이고, 별도 기계 판독 결과 `validation-verdict.json`은 모든 항목을 통과했습니다.

| 근거 | 직접 확인한 내용 |
|---|---|
| `validation/logs/check-repeat20-final.log` | 세 실제 어댑터를 포함한 73개 시험을 각각 20회, 총 1,460회 실행해 실패·건너뜀 없이 통과했고 11개 부품 포함 경계 검사도 통과했습니다. SHA-256은 `5116a3d20d04bceb0231fd18313ebfd0016f7572c39e8e174108c2161a0268fd`입니다. |
| `validation/logs/static-all.log` | 생산 번역 단위 24개의 cppcheck·clang-tidy가 통과했습니다. SHA-256은 `05755ff03df06db5e7d6b98e2957d05eda5d55a07ec1504640964c3f2e39d9ea`입니다. |
| `offline/audit.json` | 다섯 보존 원자료를 같은 후보 보고기로 각각 두 번 재생했고 각 `summary.json`이 바이트 단위로 같았습니다. 원자료 해시와 기존 표본·지표·분포·연결·시도·미계측 상태는 보존되고, 계약 필드와 자동 비교 제외만 의도대로 달라졌습니다. SHA-256은 `24eb6a3ce17ecd7ad1b7d74dbef5afd114dadd3140fb2800053354c0917d38cb`입니다. |

N05는 보존 원자료를 오프라인으로 읽었을 뿐 네트워크·손실·`netem` 실험을 다시 실행하지 않았습니다. 반환 스트림 복사 비용의 귀속은 D1 당시 변경 대상이 아니었으며, 후속 D2가 새 원자료에서 이 경계를 별도로 바꾸었습니다. 이 절의 개정값 1 자료는 당시 의미로 계속 보존합니다.

## G004 레코드 연산 귀속과 서버 구간 검증

`ff27f615fbfb08d585b0065a9c0503de796ed4a0`을 기준으로 기존 원자료에서 레코드 귀속과 서버 ClientHello→Finished 구간을 만드는 보고 기능을 확인했습니다. 원자료 생성자와 `measurement_contract_revision=1`은 바꾸지 않았습니다. `record_computation_attribution`은 연결별 보기로만 남고 그룹 지표·자동 비교를 만들지 않았으며, 서버 구간의 경과·CPU·사이클만 새 그룹 지표 후보입니다.

첫 통합 후보는 74개 시험 20회와 정적 검사를 통과했지만, 독립 검토에서 이전 레코드에서만 다른 메시지와 묶인 상태가 현재 I/O 경계의 `bundled=true`로 전파되는 문제를 찾았습니다. 이 시점의 `validation/`과 `offline/`은 수리 전 증거로 보존하되 최종 통과 근거로 쓰지 않습니다. 수리는 현재 경계의 선택 레코드가 참조하는 메시지 인스턴스만으로 묶임을 판정합니다. 독립 오프라인 검증기도 해독 결과의 전역 묶임 표시를 답습하지 않고, 원시 I/O 범위와 선택 레코드에서 메시지 인스턴스를 다시 계산하도록 고쳤습니다. 동명 메시지 두 개, 단일 메시지의 다중 레코드, 이전 레코드만 공유한 사례, 비성공 반환 뒤 재시도 성공, 성공 0바이트, CPU 시각 역전을 합성 회귀 시험으로 고정했습니다.

고정 기본 프로필의 세 라이브러리 자기 연결은 `integration/repair-three-library-structure.txt`에 다음 구조를 남겼습니다.

- OpenSSL 서버는 하나의 `before_send`에 ServerHello, ChangeCipherSpec, EncryptedExtensions, Certificate, CertificateVerify, Finished 여섯 인스턴스를 남겼고 `bundled=true`였습니다.
- wolfSSL과 Mbed TLS 서버는 여섯 이름을 각각 별도의 `before_send`에 남겼고 모두 `bundled=false`였습니다.
- 세 클라이언트는 모두 같은 여섯 메시지를 레코드 본문을 완성한 각각의 `after_receive`에 남겼습니다.
- 서버 추가 구간은 OpenSSL의 사건 순번 14→20, wolfSSL과 Mbed TLS의 14→30에서 생성됐습니다.

이는 고정한 실행에서 연산이 배치된 위치를 보여 주는 구조 근거입니다. 메시지의 내재적 비용, 라이브러리 순위, 일반적인 송수신 횟수를 주장하지 않습니다. 티켓 2개 시험은 ChangeCipherSpec이 서버 Finished 경계 전에, 두 NewSessionTicket과 응용 레코드가 경계 뒤에 있음을 확인했습니다. 상호 인증 실제 연결도 통과했지만, 서버 Finished 송신에서 끝나는 추가 구간은 클라이언트 인증서·Finished의 서버 검증 완료를 증명하지 않습니다.

수리 뒤의 최종 근거는 `results/review-20261015/G004/validation-r2/validation-summary.json`에 모았으며 SHA-256은 `463204683b481cf05b7ecd32e622ceb00d6dfb59b5dd900ff4634f55cc378695`입니다. 고정한 후보 보고기의 SHA-256은 `02882275241969565acb0bbd8d0a2a3cf56869ad02fb7771790d75e659e55fd8`입니다.

| 근거 | 직접 확인한 내용 |
|---|---|
| `validation-r2/logs/check-repeat20.log` | 세 어댑터를 켠 생산 Release·시험 Debug `-UNDEBUG` 빌드에서 74개 시험을 각각 20회, 총 1,480회 실행해 실패·건너뜀 없이 통과했습니다. 통합 시험 32개와 11개 부품 포함 경계 검사를 포함하며 SHA-256은 `6bef05b74b3879637e5389a7b8b0c8a9bc7f202cb7873e8176490ccdc3cc912e`입니다. |
| `validation-r2/logs/static-all.log` | 외부 소스를 제외한 생산 번역 단위 25개의 cppcheck·clang-tidy가 통과했습니다. SHA-256은 `0104e61d08142e68036fcf9ee0137b33df79e00e9b87728847da6cd4b1a2c954`입니다. |
| `offline-r2/audit.json` | 여섯 보존 원자료를 각각 두 번 재생했습니다. 원자료가 변하지 않았고 승인한 네 추가 경로를 제외한 기존 값·지표·조건·순서·비교 적격성이 직전 G003 결과와 같았습니다. 232개 연결의 귀속은 사용 가능, 24개는 이유 있는 미계측이었고, 기존 연산 구간 4,660개를 한 번씩 보존했습니다. 서버 추가 구간은 116개 사용 가능, 12개 미계측이었습니다. 사이클 표본은 없었으며 이를 측정값 0으로 해석하지 않습니다. SHA-256은 `5feda6fb0494ab091ba53119ddffa8e6329010dc7baab58a40bbb42db5aa2304`입니다. |

N05의 조회 보고서는 바이트 단위로 같았고 네트워크·손실·`netem` 실험은 다시 실행하지 않았습니다. 별도로 시도한 비정규 Release 시험 트리 전체 빌드는 G004와 무관한 `tests/control/control_test.cpp`의 반환값 미사용 경고로 실패했습니다. 이 실패를 숨기거나 제품 수정으로 넓히지 않았고, 규정한 Debug 전체 시험 관문을 별도로 통과했습니다. 반환 스트림 복사 귀속은 G004 당시에는 남은 한계였고, 후속 G005/D2가 새 개정값 2 원자료에서 변경했습니다. G004의 개정값 1 자료는 소급 보정하지 않습니다.

## G005 I/O 반환 귀속·수신 정책·ABI 2 검증

`d0cb7ae2261874edfe341a5e7c631d70d21ed788`을 기준으로 I/O 반환 캡처 경계와 수신 선행 정책을 바꾸고 어댑터 ABI를 2로 올렸습니다. 원자료 형식은 계속 `schema=1`이고, 새 측정 의미는 `measurement_contract_revision=2`로 구별합니다. 이전 개정값 1 자료를 새 귀속으로 소급 보정하지 않습니다.

소스 검토는 I/O 반환이 반환 사건 공간 예약 → 성공 스트림 바이트 복사 → 선택적 `KernelRx` 공간 예약 → 복합 스냅샷 한 번 → 양쪽 공간에 같은 스냅샷 대입 순서임을 확인했습니다. `lifecycle_capture_return_order`는 가짜 계측기가 읽히는 시점에 실제 고정 버퍼의 반환·`KernelRx` 공간과 복사한 바이트가 이미 존재하고, 두 사건에 같은 스냅샷이 대입되는지 확인했습니다. I/O 진입의 연결·호출·순번 식별 → 스냅샷 → 사건 종류·바이트 정보 → 기록 순서는 소스에서 확인했고, 부품 시험은 스냅샷이 사건 저장보다 앞임을 대조했습니다. 따라서 전체 순서는 소스 검토와 결정적 부품 시험으로 함께 확인한 것입니다. 실제 TLS 원자료는 반환·`KernelRx`의 연결·스트림 범위·스냅샷·커널 원시 시각이 보존된 것을 대조하지만, 스냅샷 전 내부 순서를 다시 증명하는 근거로 바꾸지 않습니다.

서버 기본 주 구간은 첫 성공 수신의 바이트 복사가 끝난 반환 스냅샷에서 시작합니다. 따라서 그 첫 수신의 공간 준비·복사는 서버 주 구간 전이며 해당 `io_ns`에 들지 않습니다. 나머지 반환 캡처는 각 I/O 구간에 듭니다. 복합 계측 읽기, 스냅샷 뒤 공간 대입, 관측자 복귀 비용은 여전히 남으므로 계측 비용을 제거했다거나 순수한 라이브러리 시간을 복원했다고 주장하지 않습니다.

수리 뒤 세 라이브러리 자기 연결의 클라이언트·서버 여섯 역할은 모두 기능적으로 유효했습니다. 여섯 원자료는 모두 `schema=1`, 개정값 2, `read_ahead=false`와 비어 있지 않은 근거 문구를 남겼습니다. 실제 요청 범위는 현재 레코드 머리·본문의 필요 잔여량과 맞았습니다. TLS 1.3, P-256, PSK·HelloRetryRequest 부재, 응용 교환, 연산 구간 136개의 중복 없는 귀속과 `computation+io+wait+gap=elapsed`도 확인했습니다. 이 실제 TCP 자료는 콜백 요청 범위를 보여 주지만 성공한 TCP 반환 횟수를 레코드당 두 번으로 보장하지 않습니다. 레코드당 머리·본문 두 반환은 요청량 전체를 즉시 돌려주는 통제 콜백 시험에서만 확인했습니다.

OpenSSL·wolfSSL·Mbed TLS·mock 모듈은 모두 `turtle_adapter_v2`만 내보내고 v1 호환 계층은 없습니다. 세 실제 어댑터의 수신 정책은 `false`이고, TLS 레코드를 해석하지 않는 mock은 해당 없음 `null`입니다.

첫 후보의 79×20 시험·정적 검사·오프라인 재생·타임라인은 통과했지만 후속 검토가 소유 수명과 실제 로더 거절 시험의 공백을 찾았으므로 최종 근거로 쓰지 않습니다. 초기 수신 정책 시험의 `Io`를 엔드포인트가 소유하도록 고쳐 연결보다 오래 살게 했고, 뒤의 독립 검토에서 찾은 smoke 시험의 설정·`HostServices`·임시 `Io` 수명도 엔드포인트 정리까지 연장했습니다. 수리 뒤 AddressSanitizer로 세 어댑터 자기 연결과 OpenSSL 수신 정책 시험을 통과했습니다. v1 전용 모듈은 실제 `lifecycle::run`에서 정확한 v2 진입점 누락 이유를 남겼고, 자식 프로세스의 sentinel이 생기지 않아 v1 진입점·`declaration`·`setup`을 호출하지 않았음을 확인했습니다. 이 경로는 50회 반복해 통과했습니다.

결과 후처리의 첫 실행은 Python 변수 이름 겹침으로 구조 검증 JSON을 쓰기 전에 실패했습니다. 고친 초기 산출물에도 부정확한 순서 설명이 남아 최종 근거에서 제외했습니다. 수리 뒤 타임라인 실행은 세 TLS 실행·여섯 해독·보고를 이미 끝낸 뒤 마지막 stderr 검사 셸 루프의 문법 오류로 감싸기 명령만 실패했습니다. TLS 원자료를 다시 실행하지 않고 이미 생성된 자료와 빈 stderr를 다시 검증했습니다. 개발 중 선택 힙 구조체를 직접 동등 비교하려다 컴파일되지 않은 시도는 영구 로그가 없으므로 증거로 주장하지 않습니다. 최종 시험은 스칼라·성능 카운터·힙 필드를 각각 비교합니다.

최종 근거는 `results/review-20261015/G005/validation-r2/validation-summary.json`에 모았으며 SHA-256은 `24499e17cdac90973904f327706b69919eb24cba6e08687b7cc4c7ffeadf439d`입니다. 고정한 후보 식별 파일의 SHA-256은 `afa746d02271bed822cb93c7b8797e12556a0c80bd25a324e3c5fb0640bf4b63`이고, 보고기 SHA-256은 `02882275241969565acb0bbd8d0a2a3cf56869ad02fb7771790d75e659e55fd8`입니다.

| 근거 | 직접 확인한 내용 |
|---|---|
| `validation-r2/logs/check-repeat20.log` | 생산 Release·시험 Debug `-UNDEBUG`·경고 오류 설정으로 79개 시험을 각각 20회, 총 1,580회 실행해 실패·건너뜀 없이 통과했습니다. 세 실제 어댑터, 통합 시험 35개, 11개 부품 포함 경계를 포함하며 SHA-256은 `c8b3470c2d64296f80d9710b9e40a72e70e41e6fd626f18b4f8852d17e6dda04`입니다. |
| `validation-r2/logs/static-all.log`, `clang-tidy-cli-endpoint.log` | 외부 소스를 제외한 생산 번역 단위 25개의 cppcheck·clang-tidy와 CLI 엔드포인트 전용 clang-tidy가 통과했습니다. 14개 Python 파일 구문, 부품 경계, diff 검사도 통과했습니다. 전체 정적 로그 SHA-256은 `0104e61d08142e68036fcf9ee0137b33df79e00e9b87728847da6cd4b1a2c954`입니다. |
| `timelines-r2/structural-validation.json` | 수리한 세 라이브러리 자기 연결 여섯 역할의 개정값·수신 정책·스냅샷 대응·요청 범위·TLS 구조·구간 합계를 확인했습니다. SHA-256은 `c4c6db42631187a602a833ca26f0d0a4e44383fef2b80ccc7d0b66516e54e015`입니다. |
| `offline-r2/audit.json` | 여섯 보존 원자료를 각각 두 번 재생했고 전체 출력 트리가 G004 승인 결과와 바이트 단위로 같았습니다. 의미 투영·허용 예외·구 자료 필드 합성은 없었고, 원자료와 N05 조회 결과도 변하지 않았습니다. SHA-256은 `3271d0e0992baa8a54571c1a19b068aa879d097278fde32ae820600d6acf8133`입니다. |

타임라인 수치는 WSL의 라이브러리별 단일 표본 구조 진단이며 시간 임계값을 쓰지 않았습니다. 성능 순위·개선율·통계적 차이를 주장하지 않습니다. N05는 보존 원자료만 오프라인으로 읽었고 N05 손실·`netem` 실험을 다시 실행하지 않았습니다. 이 제한은 N05 손실 실험에만 해당합니다. 정식 시험에는 손실 0의 `pure_tls_netem_actual`과 새 실제 TLS 연결이 포함되었습니다.
