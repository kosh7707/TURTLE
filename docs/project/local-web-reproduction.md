# 로컬 실험 웹과 저장소 정리의 재현 기록

2026년 11월 12일 작업입니다. 기존 독립 엔드포인트·계측 변경을 보존하고 로컬 웹, 새 경로 재현과 보관 정리를 연결했습니다. 어댑터 ABI 3·TLS schema 3·측정 계약 개정 4·제어 프로토콜 2는 그대로입니다. 개정 3 판독과 기존 연구 기능도 유지합니다.

## 별도 로컬 웹

웹 소스는 `~/TURTLE-experiment-web`의 별도 Git 저장소입니다. 원격 저장소나 배포 사이트를 만들지 않습니다. React·TypeScript·Vite로 조건 작성, 기존 형식의 프로필·명령 생성, 결과 가져오기, 독립 타임라인·사건 상세, 기존 보고서 비교를 제공합니다.

```sh
cd ~/TURTLE-experiment-web
./dev.sh
```

`http://127.0.0.1:5173`에서만 사용하며 포트 충돌 시 실패합니다. 실행·해독은 기존 TURTLE CLI에서 수행합니다. 웹은 원자료를 수정하지 않고 보고서의 통계·시간 분해·비교 판정을 사용합니다. 상세 사용법·의존성·디자인·브라우저 검증은 웹의 `README.md`, `THIRD_PARTY.md`, `DESIGN.md`, `VALIDATION.md`에 있습니다.

## 최초 상태와 보관

최초 HEAD는 `ba7d0b5`이며 작업 전 소스 222개를 보존했습니다. `~/TURTLE-archive/20261112-165546/`에는 다음 자료가 있습니다.

| 파일·경로 | 내용 |
| --- | --- |
| `initial-status.txt`, `initial-head.txt`, `initial-changes.patch` | 작업 전 Git 상태와 전체 변경 패치 |
| `initial-source.tar.gz`, `source-sha256.json` | 미추적 소스를 포함한 소스 복사본과 SHA-256 |
| `initial-artifact-inventory.json` | 최초 빌드·의존성·인증서·원자료 76,348개 파일의 경로·크기·수정 시각 |
| `moves.json` | 보관한 각 항목의 원래 위치·현재 위치·파일 지문 |
| `archive-verification.json` | 이동 후 해시와 예외 대조 |
| `inactive/` | 비활성 빌드와 참조하지 않는 옛 산출물 |
| `reproduction/` | 별도 소스·고정 의존성·빌드·설치·새 인증서·TLS 결과·명령·로그 |

활성 `build-module`, `build-tests-independent`, `.deps`, `pki`, `results/measurement-audit-20261112`를 유지했습니다. 문서와 유지하는 근거 자료가 참조하는 산출물도 연쇄 참조를 확인해 유지했습니다. 비활성 빌드 11개와 옛 산출물 65개, 합계 76개 최상위 항목을 옮겼습니다. 현재 근거로 쓰는 `artifacts/`의 11개 항목은 원래 위치에 있습니다. 실패 자료는 삭제하지 않았습니다.

이동·유지 기록에서 **33,571개 파일의 SHA-256을 재대조했고 불일치는 0개**입니다. 관리자 소유의 `artifacts/kernel-target-debug-1/attempts.jsonl` 하나는 읽기 권한이 없어 SHA-256이 미확인입니다. 해당 파일은 권한을 바꾸지 않고 같은 파일시스템의 상위 폴더 rename으로 보존했으며, 장치·inode·크기·mtime 불변을 확인했습니다. 실제 0이나 해시 검증 성공으로 표시하지 않았습니다. 개별 이동이 막힌 폴더도 이 방법으로 보관했습니다.

### 후속 요청에 따른 레거시 빌드 삭제

같은 날 사용자가 불필요한 레거시 빌드를 보관 대신 삭제하도록 요청했습니다. 위 `inactive/`로 옮겼던 빌드 11개를 삭제하고, 현재 `build-tests-independent`에도 남아 있던 폐기된 `turtle_attempt_record_test` 실행 파일과 오브젝트 폴더를 제거했습니다. 현재 CMake·Ninja 그래프에 해당 타깃이 없음을 확인했습니다. 삭제한 산출물의 할당 크기는 1,374,851,072바이트(약 1.28GiB)입니다.

옛 빌드 안의 `test-results`, `Testing`, 시험용 인증서와 구성 기록은 `legacy-build-cleanup/retained/`로 분리했습니다. 6,602개 파일의 SHA-256을 이동 전후와 삭제 뒤 대조했고 불일치는 없습니다. 실패 기록·원자료·성능 분석용 바이너리 사본을 빌드 산출물로 삭제하지 않았습니다. 관리자 소유 Python 캐시는 사용자가 제공한 인증으로 삭제했습니다.

삭제·유지 경로와 지문은 `~/TURTLE-archive/20261112-165546/legacy-build-cleanup/manifest.json`에 남겼고, 기존 `moves.json`에도 후속 삭제 상태를 기록했습니다. 따라서 앞의 보관 목록은 최초 이동 이력이며 해당 11개 빌드의 현재 존재를 뜻하지 않습니다. 활성 `build-module`, `build-tests-independent`, 의존성, 최신 재현·커밋 복제본의 빌드·설치 결과는 유지합니다. 정리 후 검사 기록은 [후속 검증](../../results/build-cleanup-20261112/verification.json)에 둡니다.

## 정리 범위

기존 변경의 `director.cpp`와 옛 부모 지휘 시험 삭제를 유지했습니다. CMake·import·호출 참조, 대체된 독립 실행·준비·원장·계측 근거 시험과 기존 연구 경로를 확인했습니다. 추가 C++ 정리는 설정의 중복 `cpu` 키·대입과 네트워크 근거의 무의미한 자기 대입 제거뿐입니다. 사용 여부를 입증하지 못한 코드는 삭제하지 않았습니다.

원자료 문서의 준비 상태 버전과 TLS 측정 계약을 분리하고 네 시나리오의 마지막 성공 API 경계를 명시했습니다. 예전 개정 3 결과와 실패 기록은 최신 성공 결과로 바꾸지 않았습니다. 개별 파일 검토·최초 스냅샷 이후 변경은 [소스 검토 기록](../../results/local-web-20261112/source-review.json)에 남겼습니다.

## 새 경로에서 재현하는 절차

인터넷은 의존성 준비 단계에서만 필요합니다. 새 `WORK`를 지정하고 이미 존재하는 결과를 덮어쓰지 않습니다.

```sh
# 깨끗한 복제본에서 실행합니다. 경로는 자기 환경에 맞게 지정합니다.
SOURCE=$PWD
WORK=/absolute/new-turtle-reproduction
DEPS="$WORK/deps"
mkdir -p "$WORK"
TURTLE_DEPS_ROOT="$DEPS" JOBS=4 scripts/build-deps.sh all

# 아래부터 의존성 다운로드를 하지 않습니다.
TURTLE_DEPS_ROOT="$DEPS" \
TURTLE_BUILD_DIR="$WORK/build-module" \
TURTLE_TEST_BUILD_DIR="$WORK/build-tests" \
REPEAT=1 JOBS=4 scripts/check.sh

python3 scripts/reproduce-local.py --source "$SOURCE" --deps "$DEPS" \
  --work "$WORK/installed-matrix" --jobs 4
```

재현 스크립트는 module 구성과 세 builtin 구성을 각각 새로 빌드하고 다른 prefix에 설치합니다. 설치된 클라이언트·서버 실행 파일로 세 라이브러리 × 두 어댑터 연결 방식 × 네 시나리오의 24쌍을 실행합니다. 현재 설치 대상은 두 엔드포인트 실행 파일이며, module 어댑터와 분석 실행 파일은 해당 새 빌드 폴더에서 사용합니다. 새 시험용 인증서, 상호 인증, 준비 연결 1개·측정 연결 2개, 양방향 16,385/16,386바이트, trace 모드를 사용합니다. 원자료의 TLS 1.3·세션 재개 꺼짐·정상 완료를 확인하고 CLI 해독·보고와 원자료 SHA-256 불변을 검사합니다. 각 명령과 출력은 별도 로그에 남습니다. 정상 완료 불가 시 즉시 실패하며 부분 결과를 지우지 않습니다.

OpenSSL 3.5.4, wolfSSL 5.8.2-stable, Mbed TLS 3.6.4의 고정 소스·해시·계측 패치는 기존 `scripts/build-deps.sh`의 계약을 따릅니다. 새 의존성·설치 prefix에서도 이 세 판을 실제 빌드했습니다. BiTHaC·ML-KEM 의존성은 새로 다운로드하지 않았으며 기존 전체 시험에서 현재 로컬 연구 구성을 확인했습니다.

## 검증과 한계

| 범위 | 확인 결과와 근거 |
| --- | --- |
| 기존 별도 시험 빌드 | 전체 97/97 CTest 통과. [로그](../../results/local-web-20261112/ctest.log) |
| 새 소스·새 의존성·새 시험 빌드 | 기본 세 라이브러리 구성 94/94 통과. 연구 의존성을 다시 빌드하지 않아 기존 구성보다 세 시험이 적습니다. [로그](../../results/local-web-20261112/source-reproduction.log) |
| 구조·정적 검사 | 11개 부품의 포함·순환 검사, cppcheck와 clang-analyzer, Python·셸 구문·공백 검사. [정적 검사](../../results/local-web-20261112/static.log) |
| 실제 설치 실행 | 24쌍, 각 역할에서 준비 1개·측정 2개 연결, 실제 해독·보고 성공. [행렬](../../results/local-web-20261112/tls-matrix.json) |
| 웹과 실제 TLS 연결 | 브라우저가 다운로드한 프로필과 화면의 명령으로 wolfSSL 클라이언트·Mbed TLS 서버를 실행하고 해독·보고·재가져오기. [검증](../../results/local-web-20261112/web-generated.json) |
| 웹 가져오기 | 위 새 경로의 24쌍·48개 엔드포인트와 보고서 가져오기. [검증](../../results/local-web-20261112/web-import.json) |
| 커밋 복제본 | 최종 소스 커밋을 별도 복제하고 새 빌드·인증서로 실제 TLS·해독·보고 경로를 확인하는 기록은 [검증 파일](../../results/local-web-20261112/clean-clone.json)에 둡니다. |

이 숫자를 성능 독립 표본 수나 절대 계측 정확도의 증명으로 합산하지 않습니다. ARM·물리 NIC·새 관리자 BPF 실행·독립 절대 시간 교정은 이번 재현에서 수행하지 않았습니다. 기존 관리자 실측과 실패 원자료는 그대로 보존합니다. 웹의 새로운 통계 엔진·TLS 구현·공격·잘못된 인증서 거절·타이밍 누출 시험은 추가하지 않았습니다.
