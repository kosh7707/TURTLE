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

이번 환경에는 clang-format 실행 파일이 없어 자동 형식 검사는 다시 수행하지 못했습니다. sanitizer, 물리 리눅스 perf 정확도, M5의 외부 OpenSSL 명령과의 연결, M6의 패킷 캡처 비교도 이번 완료 범위가 아닙니다.

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

M13·M14의 N05는 이 후속 검증 때문에 다시 실행하지 않습니다. 기존 64/64 성공, qdisc drop 94, CA 재전송 58은 정확히 한 번 실행한 고정 증거이며 loss 조건 확대도 하지 않습니다. M5의 수정하지 않은 OpenSSL 명령행 양방향 연결, M6, M7 관측자 비교는 여전히 다음 단계입니다.
