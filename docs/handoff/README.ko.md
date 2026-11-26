# TURTLE 개발 인수인계 · 2026-11-26

**다음 작업장은 `~/TURTLE`이다.** 이 세션에서 닫은 문제는 *서로 모르는 TLS 원본과 TURTLE을 개발자에게 과도한 일을 맡기지 않고 함께 빌드할 수 있는가*다. 논문용 계측 지표를 확정한 것이 아니다. 새 세션에 붙여 넣을 [프롬프트](next-session.ko.md)는 이 문서와 별도다.

**처음 읽을 순서:** [현재 작업지시서](../../task.md) → 이 문서 §1 → [빌드 계약](../build-contract.ko.md) → [공통 함수 선언](../../src/include/turtle/implementation.hpp) → [현재 시간·데이터 계약](../submission.md). 이 문서는 배경과 기존 근거이고, 이번 작업의 범위와 완료 조건은 `task.md`에서 정한다. 작업에 해당하는 소스는 §3, 직접 확인할 명령은 §5에 있다. [이전 설계 면담](../design-decisions.md)의 ‘미결’은 *그날* 기준이다.

## 1. 사용자 허락 없이 바꾸지 말 것

1. **편의성과 엄밀성은 둘 중 하나를 고르는 문제가 아니다.** SUPERCOP에서 가져올 철학은 연구자가 원래 가진 구현체와 빌드 방법으로 출발할 수 있게 하는 것이다. 일은 프레임워크가 더 하더라도, 이미 원본에 표현된 사실을 두 번 입력시키지 않는다. 단, 틀린 대상을 쉽게 빌드하는 것은 성공이 아니다. 여러 유효한 연구자 선택 사이에서 추측하지 않는다.
2. **대상은 구현체 하나이지 순위표나 보안 감사가 아니다.** 보장할 수 있는 문장은 “이 구현체가 이 구성·상대·계측 조건에서 보인 성능”이다. 정상적인 TLS 1.3 full handshake를 따른다고 가정한다. 서버 인증·mTLS 절차를 끄거나, 프레임워크가 RFC 적합성·인증서 검증을 재인증한다는 뜻이 아니다. TLS 1.3 성공 ≠ PQ 키 교환 또는 PQ 서명 사용.
3. **A(원본)는 B(TURTLE)를 모르고 B도 A를 모른다.** 두 API를 아는 유일한 *제품–구현체 코드*는 개발자의 `implementation.cpp`다. `implementation.hpp`는 B가 소유하는 중립 선언이다. 공급자별 분기·레지스트리·플러그인·강제 상속을 도입하지 않는다. TURTLE 연동을 위해 원본 패치를 요구하지 않는다. 연구자가 자기 포크에서 한 수정은 대상 자체의 일부다. `build.sh`는 A의 빌드 지식일 뿐 두 번째 런타임 접점이 아니다. OpenSSL은 사용성 예시이지 표준 구현이나 폴백이 아니다.
4. **기본 입력과 예시를 분리한다.** `implementations/`는 한 사용자의 활성 제출 슬롯이다. 제품은 사용자가 직접 수정할 비활성 `build.sh`·`implementation.cpp`와 README를 배포하며 실제 원본은 따로 준비한다. 벤더 예시는 오직 `docs/` 하위에 둔다. 자동 복사·자동 다운로드·예시 자동 선택 금지. **명시적으로** 예시를 골라 복사·수정한 순간 그것은 사용자의 활성 입력이다. 특정 라이브러리의 인기, 보드 사용률, 미래 기능을 제품의 가정으로 삼지 않는다.
5. **두 역할을 모두 연결하되 한 연결의 계측 대상은 한쪽뿐이다.** TURTLE이 같은 제출로 client와 server를 만들고 둘 다 실행한다. ‘상대편 일반 구현’은 별도 재작성한 reference TLS가 아니라 같은 제출의 비계측 역할이다. 양 역할이 필요하면 측정 대상을 바꿔 별도로 실행한다. 상대에 암호문 훅/PMU를 붙여 정보를 보충하지 않는다.
6. **실제로 관측한 사건만 붙인다.** 송신 직전은 *요청한 쓰기*, 수신 직후는 *실제 양수 반환*이다. BIO라는 특정 API, 커널 패킷 송신·도착, TLS 평문 반환과 같은 것이 아니다. 암호화된 묶음 안의 EE/SC/SCV/SF 각각에 가짜 시각을 배정하지 않는다. 전체 흐름이 끝난 뒤 방향, CH/SH 등 식별 가능한 증거로 구간을 해석한다. 관측 불가·미지원·실패는 다른 상태다.
7. **시나리오·계측 정책을 구현체에 넘기지 않는다.** 새 연결, 역할, 인증, 읽고 쓸 데이터와 순서, doctor, 예열, 반복, 실패 기록은 프레임워크 책임이다. S2/S4에서 CF를 기다렸다가 보낸 인사를 선송신으로 간주하지 않는다. 연구의 중요한 후보 통찰은 *같은 메시지와 연산이라도 종료점과 작업의 중첩에 따라 관측값이 달라질 수 있다*는 것이다. 통계적으로 유의하다는 것을 미리 전제하지 않는다.

**작업 방식:** 제품은 C/C++ 중심이고 빌드 자동화는 셸·CMake다. Python 없이, 작은 함수와 명확한 책임을 우선한다. 새 설명은 소스의 주석 더미 대신 명세·이름·테스트에 남긴다. 원본 프로젝트 자체의 도구(예: Perl)는 그 원본의 요구사항이다. “의존성 최소화”를 “현 코드에 외부 의존성이 전혀 없다”로 고쳐 쓰지 않는다. 기존 컨트롤러의 JSON 의존성이 있고, 개발자에게 JSON 빌드 명세를 요구하지 않는 것은 별개의 일이다.

**기존 checkout 업데이트 전:** 예전에 Git에서 무시하던 레시피와 브리지가 있으면 [안전한 업데이트 절차](../../implementations/README.md#기존-작업-트리를-업데이트한다면)를 먼저 따른다.

**Git과 레거시 처리:** `~/TURTLE`은 개인 저장소다. 별도 브랜치 없이 `main`에서 직접 작업하고, 필요하면 커밋을 나누거나 합치는 등 로컬 Git 이력을 자유롭게 정리한다. 현재 설계에서 더는 쓰지 않는 레거시는 하위 호환을 위해 남겨두지 말고 휴지통으로 옮긴다. 판정 기준은 현재 설계에서 맡은 역할이지 커밋 여부가 아니다. 진행 중인 작업이나 `implementations/`의 사용자 제출물을 미커밋·Git 무시 상태라는 이유만으로 폐기하지 않는다.

## 2. 합의·현재 구현·미결을 구분할 것

| 주제 | 채택한 경계 | 현재 상태 / 다음에 구분할 것 |
|---|---|---|
| 빌드와 제출물 | `bench.sh`가 `implementations/build.sh WORK PREFIX [native argv…]`를 호출한다. 개발자가 원본 빌드 방법을 제공하고 B가 C를 컴파일해 두 역할에 링크한다. | 현재 backend는 로컬 Linux, ELF 공유 라이브러리, pkg-config 소비 정보다. Make/CMake 구분은 레시피 내부 문제. 모든 정적 라이브러리·크로스 빌드·원격 보드를 이미 지원한다는 뜻은 아니다. |
| 예시의 지위 | 일반 규격이 먼저, 특정 사용자의 출발점은 docs에서 선택한다. | OpenSSL·wolfSSL·GnuTLS에는 레시피와 연결 코드 예시가 있다. Mbed TLS 4.3.0은 **네이티브 SDK 레시피만** 있다. 임베디드 보드 실험·PQ 협상·완성된 TURTLE 참가자를 제공한 것으로 세지 않는다. |
| 수명주기 | doctor는 ping이 아니라 **요청한 조건에서 실제 전체 시나리오 1회**다. 성공·지표 가용성을 나누고, doctor·예열·본 표본을 합산하지 않는다. 반복 횟수는 외부 설정, 기본값 별도. | 현재 제출 경로는 인증×시나리오×계측 역할마다 doctor를 먼저 수행한다. 기본 S3/client/서버 인증, 예열 1·본 표본 2. `--build-only`는 그 **이전**에 끝난다. 종료점 시각을 기록해도 남은 프로토콜 처리는 끝까지 진행해야 한다. |
| 관측과 집계 | Recorder는 저비용 순수 계측값, Aggregator는 사후 파싱·사건 해석·조건별 집계를 맡는다는 설계다. Analyzer와 Aggregator를 명칭만 다른 두 단계로 의무화하지 않는다. | 현재 제출 역할의 CSV는 사건, 단조 시각, 바이트 **수**다. 레코드 본문 전체의 복호화·분해기가 아니다. job의 증거 확인과 기존 SDK JSON 분석기도 있다. 설계 속 모든 등장인물이 완성된 독립 모듈인 것으로 그리지 않는다. |
| black/white box | 측정 대상 쪽에서 양 끝만 볼지, 메시지/묶음 증거까지 남길지는 **계측 깊이**다. 비계측 peer라는 구분과 직교한다. | 현재 peer에는 암호문 훅과 PMU를 설치하지 않지만 교환 완료 확인용 SDK 이벤트는 있다. ‘상대의 계측 오버헤드가 완전히 0’이라고 쓰지 않는다. |
| 지표 | 벽시계 지연은 독립적으로 의미가 있다. cycle은 가능할 때 대상 스레드의 구간 전후 카운터 차다. 메모리 peak를 두 시점에서 추정하지 않는다(현재 범위 밖). | Linux `perf_event_open` 사용 가능성과 권한은 별도다. 외부 `perf` 명령 필수, 실시간→cycle 환산, PMU 부재→모든 지연 폐기 모두 아님. 기존 SDK의 적격 표본과 새 훅 원자료의 자격을 다음 단계에서 설계한다. |

### S0–S4: 지켜야 할 의미와 아직 정하지 말아야 할 수치

공통 full handshake는 CH → SH → 보호된 서버 메시지 묶음 → 보호된 클라이언트 완료 경로다. 서버 인증은 [EE, SC, SCV, SF] / CF, mTLS는 [EE, CR, SC, SCV, SF] / [CC, CCV, CF]. 선택적 호환 CCS는 핸드셰이크 메시지가 아니다. 대괄호는 관측상 묶음이지 “항상 하나의 TLS 레코드 또는 소켓 read”라는 보장이 아니다.

| Task | 강제하는 의존성 |
|---|---|
| S0 | 핸드셰이크만 한다. CAD/SAD 없음. |
| S1 | 클라이언트가 핸드셰이크 후 CAD를 보낸다. 응답 없음. 연구에서 원하는 서버 측 ‘수신까지’와 앱 내부 처리·검증 완료 시각을 혼동하지 않는다. |
| S2 | SF 뒤 서버는 **CF를 기다리지 않고** SAD₁을 보낸다. 클라이언트의 CF 송신과 SAD₁ 수신 사이에 추가 순서를 강제하지 않는다. CAD는 없다. |
| S3 | 핸드셰이크 후 CAD. 서버는 자기 핸드셰이크를 완료하고 **CAD 전체를 확인한 뒤에만** SAD₂로 응답한다. |
| S4 | S2의 SAD₁ 분기와 S3의 요청/응답이 공존한다. CF → CAD, 서버 핸드셰이크 완료 및 CAD 전체 확인 → SAD₂. SAD₁은 요청의 응답이 아니다. 서버 스트림의 인사와 응답 순서는 유지한다. |

- 서로 엇갈리는 방향의 TCP SEQ 값은 직접 비교할 수 없다. 필요하다면 방향별 바이트 범위와 ACK·관측 위치를 함께 쓰되, 그것도 TLS가 처리한 시각은 아니다. 순서를 못 밝힌 표본을 몰래 버리거나 의도적으로 한 순서만 허용하지 않는다. netem RTT/loss·veth·flush 등이 분포에 영향을 준다는 가설과 실제 원인을 구분한다.
- 예컨대 연구 논의의 S2 **클라이언트 SAD₁ 수신 / 서버 CF 수신**은 서로 다른 종료점이다. 현재 [별도 SDK](../endpoint.md#tasks)는 S2 서버를 인사 쓰기 수락으로 다룬다. 둘은 동의어가 아니다. composite accept가 돌려주지 않은 내부 시각은 `null`로 남긴다. S3/S4도 첫 응답 바이트와 요청한 N바이트 전체 수신을 같은 TTFB라 부르지 않는다. **앞선 논의의 목표, 현재 코드의 종료점, 추후 확정할 관측 층**을 구분할 것.

## 3. 무엇이 어디서 실행되는가

| 경로(이 저장소 기준) | 읽어야 할 이유 |
|---|---|
| [bench.sh](../../bench.sh) → [submission-build.sh](../../tools/submission-build.sh) → [submission-link.cmake](../../tools/submission-link.cmake) | 처음은 사용자 진입점, 가운데는 native recipe 호출/종료 코드·재개, 마지막은 사설 모듈 선택/브리지 컴파일/두 링크/로더 사전 확인. 지문은 [별도 도구](../../tools/submission-fingerprint.cmake). |
| [공통 헤더](../../src/include/turtle/implementation.hpp) / [런타임 계약](../submission.md) | 직접 구현할 일곱 함수: setup/free, set_hooks, connect, accept(선택적 greeting), app_send/recv. 소켓은 B 소유, 구현체는 연결 fd를 빌린다. hook 값이 쓰기 결과를 바꾸지 않는다. |
| [job.cpp](../../src/submission/job.cpp) / [role.cpp](../../src/submission/role.cpp) | job은 양쪽 실행 경로를 넘겨 실제 `turtle run`을 호출한다. role은 소켓/TLS 생명주기와 대상 쪽 훅을 연결한다. 링크만 확인하는 명령에서는 둘의 TLS 코드를 실행하지 않는다. |
| [endpoint.cpp](../../src/native/endpoint.cpp) / [evidence.cpp](../../src/native/evidence.cpp) / [stream.cpp](../../src/native/stream.cpp) | 실제 시나리오 구동, 사건 해석, 프로세스 제어와 실행 결과가 만나는 곳. SDK 경로와 제출 경로가 일부 코드를 공유한다. [과거 SDK 계약](../endpoint.md)을 새 연구 끝점의 정답으로 가져오지 않는다. |
| [선택형 레시피](../examples/submissions/README.md) / [중립 빌드 회귀](../../tests/submission-build-contract.sh) | 전자는 개발자의 선택 재료, 후자는 특정 벤더가 없는 합성 라이브러리로 실제 두 역할 **링크**만 검사한다. 어느 것도 실행 시 벤더 검색 목록이 아니다. |

## 4. 검증 이력: 무엇을 다시 사용할 수 있는가

아래 경로는 **실험 당시 이 워크스테이션에서의 위치**다. `~/TURTLE-build-study`를 영구 보관하거나 제품 실행에 요구한다는 뜻이 아니다. [현재 작업지시서](../../task.md)에 따라 필수 근거는 저장소로 이관하고, 역사적 원자료는 필요할 때 별도 보관한다. 이관과 독립 재현이 끝나기 전에는 원본을 삭제하지 않는다. `/tmp/temp`, `/tmp/tteemmpp`, 이전 채팅 또는 OMX 상태도 제품 원본이 아니다.

| 확인한 질문 | 근거 (`~/TURTLE-build-study/` 아래) | 증명하지 않는 것 |
|---|---|---|
| 어떤 노동을 줄여야 하나? | `build-criteria.ko.md`의 낮은 결합도·중복 입력·선택 횟수·잘못된 성공 기준. `build-methodology.ko.md`는 A/B/C 일반론 및 과거 축소 실시예. | 사람을 대상으로 측정한 사용성 점수. |
| 원본과 사용 메타데이터를 분리할 수 있나? | `experiments/20261126T0132Z/results.ko.md` — 3종의 원본 빌드·프로브·잘못된 생성 헤더/로더 대조. | 실제 TURTLE 시나리오, 또는 모든 제출에서 헤더 출처가 자동 입증됐다는 주장. |
| 두 역할을 TURTLE이 실제 실행할 수 있었나? | `experiments/20261126T0146Z/results.ko.md`, `cases.tsv` — 당시 고정본에서 OpenSSL 20/20, wolfSSL 12/20, GnuTLS 16/20 교환·출처·측정 측 훅 확인. 미지원 12개는 각 제출의 서버 선송신 한계이지 폴백으로 성공시키지 않았다. | **이전** 통합 증거이지 이번 빌드 판정표가 아니다. 그때 기존 SDK 자격 표본은 0. 48은 지연·cycle에 대한 표본 수도, 성능 순위도 아니다. 숫자를 개선하려고 이번 단계에서 판정을 바꾸지 않았다. |
| docs의 레시피가 실제로 설치·링크되나? | `experiments/examples-20261126T0210Z-FI96hE6S/RESULT.ko.md` — OpenSSL/wolfSSL/GnuTLS 각 독립 native build, 생성 헤더와 두 역할의 같은 연결 목적 파일 대조. `experiments/mbedtls-4.3.0-recipe-20261126/RESULTS.md` — 공식 Mbed TLS 원본, 기본/혼합 소비자 대조, 사설 DSO와 링크용 fixture. | 이번 작업은 성능 시험이 아니다. Mbed TLS의 실제 제출용 연결 코드·원격 보드·PQ 지원 보증 없음. |
| 현재 루트에서 시작해도 되나? | `experiments/contract-handoff-20261126-pBxlSo8s/`: `user-walkthrough/command`, `user-walkthrough/verified`, `build-contract.log`, `ctest-build-only.log`. wolfSSL 소스만 있을 때는 미활성, **명시적으로** docs에서 선택한 뒤 신규 prefix로 실제 루트 명령 한 번에 두 역할 링크. | 로더의 사전 조회는 두 TLS 프로세스의 실측이나 보안 감사가 아니다. |

논문 근거가 필요하면 `~/TURTLE-paper/references/`의 RFC 9846, *Benchmarking Post-Quantum Cryptography in TLS*, *The Performance of Post-Quantum TLS 1.3*, *A performance evaluation framework for post-quantum TLS* 원문부터 확인한다. 이 문서가 문헌이나 시장 점유율 조사를 대체하지 않는다.

## 5. 다음 세션의 첫 10분

```sh
cd ~/TURTLE
git status --short --untracked-files=normal
git rev-parse --short HEAD
./bench.sh --help
sh tests/submission-build-contract.sh
```

테스트는 임시 트리에서 실행되며 실제 사용자 슬롯을 채우지 않는다. 빈 슬롯이나 아직 기본 틀인 슬롯에서 `./bench.sh --build-only`가 해당 파일을 표시하고 종료 2를 내는 것은 정상이다. 예시가 필요하면 [명시적 활성화 순서](../examples/submissions/README.md)를 따르되, 기존 소스/제출물을 덮어쓰지 않는다. 위 테스트에는 [빌드 전제 조건](../build-contract.ko.md)이 필요하다. 더 확인하려면:

```sh
check=$(mktemp -d "${TMPDIR:-/tmp}/turtle-handoff.XXXXXXXX")
cmake -S . -B "$check" -DBUILD_TESTING=ON -DTURTLE_BUILD_REFERENCE=OFF
ctest --test-dir "$check" --output-on-failure -R '^(submission_build_contract|submission_entry_requires_inputs|component_boundaries|source_language_policy|source_language_policy_regression)$'
```

인계 시점 `main`의 기반 커밋은 `6e706219aa112f10e52221dc9973131311dbde1f`이다. **그 커밋만 checkout하면 이 인계의 상태가 아니다.** 빌더·제출 헤더·역할 실행기·문서 및 별도의 네이티브 launch profile/보고서 작업이 미커밋 상태로 공존한다. 이 턴은 기존 OpenSSL 원본 checkout을 보존하고 제품이 제공하던 예시 파일만 docs로 옮겼다. `implementations/`의 사용자 파일은 기본 Git 무시 대상이다. 이 커밋은 대조용이지 보존할 기준선이 아니다. 작업 트리를 먼저 읽고 §1의 Git·레거시 방침에 따라 정리한다.

위 표 마지막 행의 기록 디렉터리에는 `worktree-status.txt`, `source-files.sha256`, `product-sources.tar.gz`가 있다. 아카이브는 인계 당시의 제품 소스·문서·테스트(새 파일 포함) 대조용이다. 사용자 TLS 원본, 인증 키, .git, .omx, 캐시와 결과 디렉터리는 들어 있지 않다. 기본은 현재 작업 트리를 읽는 것이며, 비교가 필요하면 별도 빈 경로에만 푼다.

**다음 개발 단위:** 빌드 계약 회귀와 실제 제출물의 빌드부터 검증한다. 그다음 S0 수명주기와 S0–S4의 동작을 계측하고, 코드 리뷰·정리 후 연구 폴더·백업 없이 재현한다. 시험 범위와 합격선은 [작업지시서](../../task.md) 한 곳에서 관리한다.
