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

### PKI 시각 역행 수정

`scripts/make-pki.sh`는 이제 발급 시작 시각을 한 번만 읽고 root·intermediate·leaf 전체에 같은 유효 기간을 사용합니다. `notBefore`는 발급 시각보다 300초 앞, `notAfter`는 발급 시각보다 3,650일 뒤입니다. OpenSSL 3.0에서도 명시적 시작·종료 시각을 지정할 수 있도록 `openssl ca`를 사용하며 정상 `openssl verify`를 유지합니다.

ECDSA P-256·RSA-2048·Ed25519 잎과 체인 길이 1~3의 9조합을 각각 두 번 system OpenSSL 3.0과 고정 OpenSSL 3.5에서 확인했고 모두 통과했습니다. 추가 시험은 `date`가 발급 과정에 돌려주는 시각만 실제 검증 시각보다 240초 앞당겼고 host 시계를 바꾸지 않았습니다. 그 상태에서 만든 인증서도 실제 시각의 정상 검증을 통과했습니다. 이 결과는 이전 `certificate is not yet valid` 원인을 수정했음을 보여 주지만, `results/validation-20261015-resume/check-45-repeat20.log`의 과거 실패 사실을 지우지는 않습니다.
