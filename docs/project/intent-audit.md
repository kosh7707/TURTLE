# 의도된 동작 점검 — 2026-11-12

`f238242`의 깨끗한 작업 상태에서 시작했습니다. 설정·준비 합의, 네 시나리오의 TLS API 순서, 계측·부분 입출력, 해독·보고서, 로컬 실행기와 웹의 자료 결합을 따라가며 정상 실행을 확인했습니다. 증거와 재현 스크립트는 로컬 `results/intent-audit-20261112/`에 보존합니다. 이 디렉터리는 Git 추적 대상이 아닙니다.

## 발견과 수정

| 항목 | 수정 전 | 수정 후와 회귀 근거 |
|---|---|---|
| Finished+Ping 묶음 송신 | `IO_SEND_RETURN`에는 실제 제출량이 있지만 `output_flush` 호출 종료의 요청·반환 필드는 0 | `IoResult`와 미제출 요청량을 보존합니다. 부분 성공 → `WantWrite` → 재성공의 단위 시험과 실제 세 라이브러리의 I/O 대조를 추가했습니다. |
| 보고서 그룹 적격 표시 | 진단 모드·상대 자료 누락은 비교 단계에서 제외되지만 그룹 적격 표시는 참일 수 있음 | 실제 단일 그룹 판정을 내보내고 제외 이유를 남깁니다. 기술통계와 그룹 간 비교 규칙은 유지합니다. |
| 웹의 자료 결합 | 같은 종료 순번이면 다른 경계 시각을 가진 보고서를 표시할 수 있고 null 실행 ID도 통과 | 원자료 시작·종료 순번과 시각·계약·연결 중복을 대조하고 비어 있는 ID는 자동 결합하지 않습니다. |
| 웹의 준비 조건 | 준비·측정 연결의 개별 한도만 검사 | 엔드포인트와 같은 합계 1025개 한도를 적용합니다. 빌드 명령은 공통 `scripts/build.sh`를 사용하고 절대 프로필 경로를 정확히 안내합니다. |

수정 전 실패한 회귀 시험은 `flush-regression-before.log`, `report-regression-before.log`, `web-regression-before.log`에 남습니다. 실패 원자료를 수정하거나 성공 자료로 교체하지 않았습니다. ABI 3·TLS schema 3·측정 계약 개정 4·제어 프로토콜 2를 유지하며 개정 3 판독도 유지합니다.

## 실제 TLS 범위

| 실행 | 확인한 내용 |
|---|---|
| 기본 조합 144쌍 | 세 라이브러리 × 네 시나리오 × timing/memory/trace × 두 송신 정책 × 서버/상호 인증 |
| 레코드 경계 9쌍 | 각 라이브러리의 16383·16384·16385바이트, 준비 1개·측정 2개 연결 |
| 교차 구현 24쌍 | 서로 다른 라이브러리의 여섯 방향 × 네 시나리오, 클라이언트 timing·서버 memory/trace, 비대칭 크기, 준비·측정 연결 |
| 관측자 끔 12쌍 | 세 라이브러리 × 네 시나리오. 관측하지 않은 I/O·서버 주 구간을 0으로 만들지 않음 |
| 직접 소켓 3쌍 | OpenSSL의 지원되는 세 시나리오. 미관측 스트림의 해독 완료를 주장하지 않음 |
| 큰 묶음 송신 3쌍 | 각 라이브러리의 262145/262162바이트, 작은 소켓 버퍼. 각 실행에서 부분 송신 15회·`WantWrite` 15회를 실제 관측 |
| PMU·반복 컨텍스트 3쌍 | OpenSSL timing, 컨텍스트마다 준비 1개·측정 3개 연결. 요청한 user PMU가 양쪽에서 available이며 컨텍스트 단위를 보존 |

합계 **198쌍, 준비 연결을 포함한 TLS 연결 273개**입니다. 기존 CTest와 별도로 실행한 수치이며 성능 비교 표본 수를 뜻하지 않습니다. 웹에서 만든 프로필·명령으로 wolfSSL 클라이언트/Mbed TLS 서버의 Finished+Ping 한 쌍도 추가 실행했습니다.

관측 가능한 실행은 양쪽 스트림 바이트의 일치, TLS 1.3 전체 핸드셰이크, 인증 결과, 해독된 응용 길이, 재개·HelloRetryRequest 없음, 연속 사건 순번을 확인했습니다. 각 시나리오 의미에서 마지막 성공 호출을 독립 선택하고 시간 분해·CPU 차분·힙 구간 최대값을 원자료와 대조했습니다. 준비 연결은 통계에서 빠지며 같은 컨텍스트의 연결을 독립 표본으로 합치지 않습니다. 독립 시계의 교차 엔드포인트 시간은 null입니다.

`tls-matrix/verification.json`, `extended-verification.json`에 개별 결과가 있습니다. 원자료를 바꾸지 않고 **196개 보고서**를 새 `report-final/`에 다시 생성한 결과, **282개 그룹 적격 표시**가 바로잡혔고 기술통계·측정 구간·기존 비교 결과는 동일했습니다. 모든 입력 JSONL의 SHA-256도 같았습니다. `report-replay-verification.json`에 남깁니다.

## 빌드·회귀·웹

- 소스 Release 빌드와 별도 Debug 시험 빌드, 전체 **98/98 CTest**를 통과했습니다. 조회·BiTHaC·ML-KEM·기존 네트워크 시험도 포함합니다.
- cppcheck 전체 검사, clang-analyzer 전체 검사와 보고서 수정 뒤 재검사, 11개 부품 경계 검사·자체 시험을 통과했습니다.
- 웹 TypeScript·생산 빌드, **24개 단위 시험·9개 Chromium 시험**을 통과했습니다. 프로필 다운로드, 헬퍼 빌드·실제 TLS·해독·보고·재가져오기, 이전 깨끗한 설치 경로의 24쌍 가져오기를 포함합니다.
- 10만 사건의 지연 로딩·읽기 취소·가상 스크롤, 1280·1440·1920px와 키보드, 실행 중 외부 요청 없음도 다시 확인했습니다.

주요 로그는 `final-ctest.log`, `final-cppcheck.log`, `clang-analyzer.log`, `final-report-analyzer.log`, `final-boundaries.log`, `web-final-unit.log`, `web-final-browser.log`입니다. 새 결과만 만들었으며 활성 빌드 두 개를 재사용했습니다.

## 재현과 한계

```sh
REPEAT=1 JOBS=4 STATIC_CHECKS=1 scripts/check.sh
scripts/make-pki.sh results/new-audit/pki
python3 -B tests/integration/measurement_audit.py \
  --build build-module --pki results/new-audit/pki \
  --output results/new-audit/tls-matrix
```

확장 실행의 정확한 입력은 `extended/*/profile.json`, 명령은 각 `run.log`에 있습니다. `extended_scenarios.py`와 `replay_reports.py`도 증거 폴더에 보존합니다. 재실행할 때는 새 출력 경로를 사용합니다. 처음 점검 명령에서 인증서 폴더를 잘못 지정한 실패와 보고서 옵션 순서를 잘못 지정한 실패는 각각 `full-matrix/`, `extended-preflight/`에 남겼고, 올바른 경로·명령으로 새 디렉터리에 실행했습니다.

이미 준비된 의존성을 사용한 WSL2 로컬 기능 점검입니다. 새로운 다운로드·관리자 설정 변경·물리 NIC 수집은 하지 않았습니다. 물리 장비의 성능 순위나 계측의 절대 정확도, 모든 가능한 입력의 정확성을 입증하는 시험은 아닙니다. 공격·잘못된 인증서 거절·타이밍 누출 시험은 추가하지 않았습니다.
