# TURTLE 제출 빌드 및 S0–S4 검증

[검수 기준](../task.md) · [제출·증거 계약](submission.md) · [빌드 계약](build-contract.ko.md) · [연구 자료 이관](build-study-migration.ko.md)

**완료.** 최종 격리 실행에서 빌드 계약 **3/3**, OpenSSL·wolfSSL·GnuTLS의 독립 링크 **3/3**, 선택한 OpenSSL의 S0–S4 **20/20 조합·40/40 본 시도**가 통과했다. 인증 실패·복구와 CF 보류 통제도 예상대로 동작했다. 코드/구조 독립 리뷰, 연구 자료 이관과 외부 백업 검산을 마쳤다. `~/TURTLE-build-study` 없이도 제품 빌드와 이 검증을 재현할 수 있다. 연구 원본은 홈 최상위에서 보관소로 옮겼고 별도 백업도 보존했다.

## 1. 재현 명령

이 머신의 검증·재현 폴더 5개와 연구 원본 `TURTLE-build-study/`는 `~/.local/share/turtle/archive/2026-11-26`(이하 **A**)의 `home/` 아래로 옮겼다. 이후 `E/…`는 입력·검산 기록을, `R/…`는 당시 최종 격리 실행의 원자료를 가리킨다. 파일을 열 때는 새 위치를 사용한다.

```sh
A="$HOME/.local/share/turtle/archive/2026-11-26"
E="$A/home/TURTLE-validation-20261126"
R="$A/home/TURTLE-final-validation-20261126"
```

작업 트리 최상위 정리 후의 독립 재실행은 별도 경로 `~/.local/share/turtle/validation/2026-11-26-root-layout-final/`에 기록한다. 그곳의 `verification.txt`, `matrix/*/build-only-proof/`, `index/{cases,connections}.tsv`를 확인한다. 이번 구조 변경의 CTest·SDK 검사 및 코드 리뷰는 `A/root-layout/logs/`와 `A/root-layout/review/`에 둔다. 아래 원래 표본과 합산하지 않는다.

원자료에는 실행 당시 절대경로가 그대로 남아 있다. 옛 경로의 홈 최상위 링크는 만들지 않았다. 보관·복원 안내는 `A/README.ko.md`, 경로 변경 전 발행 문서는 `A/published/docs/`에 있다.

리눅스에서 bubblewrap의 사용자·마운트·PID·네트워크 네임스페이스가 필요하다. C/C++ 컴파일러, CMake, GNU Make/binutils/tar/coreutils, pkg-config, flock, jq, ip, timeout, OpenSSL CLI가 필요하고 OpenSSL 원본의 Configure는 Perl을 쓴다. GnuTLS의 호스트 개발 의존성은 nettle/hogweed, GMP, libtasn1, libidn2, p11-kit이다. 검산기는 큰 JSON 정수 리터럴을 손실 없이 읽고 다시 출력하는 jq가 필요하다(사용 환경: 1.8.1). 시작할 때 정밀도 전제를 검사하고, 맞지 않으면 낮은 정밀도로 대신 계산하지 않고 중단한다. 실행 호스트의 버전과 실제 마운트, 상속 환경, 루프백 주소는 각각 `R/host.log`와 `R/isolation.log`에 남는다. Linux 호스트 도구는 읽기 전용으로 빌려 쓰므로 다른 OS·컴파일러의 재현까지 증명하지 않는다.

### 고정 입력

다음 네 **소스 아카이브**만 `E/inputs/`에 둔다. 이미 설치된 TLS/JSON SDK를 복사하지 않는다. [검증 드라이버](../tools/validation/build-matrix.sh)는 네 해시를 하드코딩해 검사한 뒤 JSON을 오프라인으로 부트스트랩한다. 검증에 사용한 출처는 `E/inventory/input-provenance.txt`에 기록했다. 버전 번호는 TLS 런타임의 성능 우열을 나타내지 않는다.

| 파일 | 실제 출처 | SHA-256 |
|---|---|---|
| `openssl-2d1c10a592677ff34cdf60bd59c431d835a1fc26.tar.gz` | 수정 없는 작업 슬롯의 OpenSSL Git commit `2d1c10a592677ff34cdf60bd59c431d835a1fc26`에서 `git archive --format=tar --prefix=openssl-2d1c10a592677ff34cdf60bd59c431d835a1fc26/ <commit>`을 만들고 `gzip -1`로 압축 | `915a1844aea2c0ff3c15f16572fe110ff3840af0aa675f5e83c95b5ae85f4cc4` |
| `wolfssl-5.9.4.tar.gz` | v5.9.4-stable 소스; 이 머신의 기존 `.deps/cache` 아카이브. [의존성 명세](../tools/dependencies.json)의 핀과 일치 | `7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57` |
| `gnutls-3.8.14.tar.xz` | GnuTLS 3.8.14 배포 소스; 기존 연구의 `experiments/20261126T0132Z/gnutls/upstream/`에서 원본 아카이브를 복사한 뒤 연구 폴더를 가렸다. 이 사본의 무결성은 확인했으나 릴리스 서명을 다시 검증하지는 않았다 | `7e2d258071f5db9620aa7ff34259331d004f7beafa3eb18560cfaf60acfbf02a` |
| `json-3.12.0.tar.xz` | nlohmann/json 3.12.0 헤더 배포본; 기존 로컬 캐시에서 가져온 소스 아카이브. [의존성 명세](../tools/dependencies.json)의 핀과 일치 | `42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa` |

### 독립 실행

저장소 루트에서 [정리 후 독립 검증 드라이버](../tools/validation/clean-room.sh)를 호출한다. 이 머신에서는 보관소의 `E/inputs`를 입력으로 복사한다. 격리 안에서는 보관소 전체(연구 원본 포함)와 예전 연구 경로가 모두 보이지 않는지 확인한다. 드라이버가 원 작업 트리와 입력의 원래 경로도 자동 확인한다. 새 출력은 보관소 밖에 둔다. 다른 머신에서는 입력과 가릴 경로를 실제 위치로 바꾼다. `clean-room.sh`에 넘길 마지막 출력 디렉터리는 아직 없어야 한다.

```sh
A="$HOME/.local/share/turtle/archive/2026-11-26"
E="$A/home/TURTLE-validation-20261126"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/turtle-replay.XXXXXXXX")
run="$scratch/final"
JOBS=6 CMAKE_BUILD_PARALLEL_LEVEL=3 \
  tools/validation/clean-room.sh "$E/inputs" "$run" \
  "$HOME/TURTLE-build-study" "$A"
cat "$run/verification.txt"
```

이 명령은 정해진 실행 소스만 내보낸다. 네 입력 아카이브를 검사하고, 이름이 지정된 CTest 3건과 별도 작업 트리의 3종 `./bench.sh --build-only`를 수행한다. 빌드가 끝나면 선택한 OpenSSL 작업을 재개해 연결별 증거를 대조하고 두 가지 별도 통제를 실행한다. `JOBS`는 native 빌드 병렬도이며 native 인자가 아니다. 다음은 드라이버 내부의 재개 명령이다. 직접 호출하려면 기존 빌드와 동일한 환경·레시피·브리지·원본·native argv를 유지한다. 독립 드라이버가 이미 재개한 job에는 이 명령을 **다시** 호출하지 않는다.

```sh
# 기존 빌드와 같은 환경에서, runs/가 아직 없는 OpenSSL job에만 적용.
V="$run/matrix/openssl"
(
  cd "$V/tree"
  export CMAKE_PREFIX_PATH="$run/matrix/deps/prepared/json-3.12.0/install"
  TURTLE_BUILD_DIR="$V/framework" ./bench.sh --resume "$V/job" \
    --scenario all --role both --auth both --warmups 1 --repetitions 2
)
```

벤더별 루트 명령은 `TURTLE_BUILD_DIR="$V/framework" ./bench.sh --build-only --out "$V/job"`이다. `R/matrix/*/tree/implementations`에는 [레시피 예시](examples/submissions/README.md)를 격리 트리별로 명시적으로 복사했다. 시나리오 재개는 세 빌드 중 OpenSSL에만 수행했다. `--use`는 벤더 고정 기능이 아니라 복수 링크 후보 중 유효한 소비 계획을 선택하는 수단이다. 이 세 실제 제출에서는 없어도 각각 한 계획으로 결정됐다. 선택·재개의 양성·음성 사례는 합성 계약 회귀로 따로 검사한다.

## 2. 빌드 판정

최종 격리 실행 **R**의 판정이다. 세 CTest를 195.67초에 통과했다. `R/source.sha256`은 `E/ultragoal/final.sha256`과 같고, 실행·테스트 소스 163개를 대조한 manifest SHA-256은 `5a0c0f3edd70b80080616ccbad748b4e07a678e4b18a5cc3b70a1dfafe00e2ef`이다. 아래 로컬 경로는 **R** 기준이다.

| 계약 회귀 | 성공/요청 | 판정 기준 | 근거 |
|---|---:|---|---|
| `submission_entry_requires_inputs` | 1/1 | 빈 슬롯에서 종료 2, 빌드·출력 디렉터리 미생성 | `matrix/contracts/ctest.log`, [테스트](../tests/submission-entry.sh) |
| `submission_build_contract` | 1/1 | 공백·빈 값·별표를 포함한 argv 그대로, 생성 헤더, 공통 브리지 객체, 사설 DSO; 동일 입력 재개와 선택 성공, 변경 입력·SDK·누락 메타데이터의 재개/실행 거절 | 같은 CTest 로그, [계약 테스트](../tests/submission-build-contract.sh), [합성 레시피](../tests/fixtures/submission-recipe.sh) |
| `submission_recipe_failure` | 1/1 | 시험 레시피의 종료 23 및 로그 보존; 역할 바이너리와 시나리오 결과 미생성 | 같은 CTest 로그, [테스트](../tests/submission-entry.sh) |

| 실제 제출 / 레시피 옵션 | 선택 모듈 | 확인한 private 헤더 / DSO | 성공/요청 · 판정 | 근거 디렉터리 |
|---|---|---|---|---|
| OpenSSL 4.2.0-dev (`2d1c10a5…`); Configure `shared no-tests --libdir=lib`, job의 private prefix/openssldir | `openssl` | `openssl/opensslv.h` / `libssl.so.4`, `libcrypto.so.4` | 1/1 · 통과 | `matrix/openssl/` |
| wolfSSL v5.9.4-stable; CMake `BUILD_SHARED_LIBS=ON`, `WOLFSSL_EXAMPLES=no`, `WOLFSSL_CRYPT_TESTS=no`, job의 private install prefix | `wolfssl` | 생성된 `wolfssl/options.h` / `libwolfssl.so.46.0.0` | 1/1 · 통과 | `matrix/wolfssl/` |
| GnuTLS 3.8.14; `--enable-shared --disable-static --disable-doc --disable-tools --disable-tests --disable-full-test-suite --disable-cxx --disable-nls --with-included-unistring`, job의 private prefix/libdir | `gnutls` | `gnutls/gnutls.h` / `libgnutls.so.30.43.0` | 1/1 · 통과 | `matrix/gnutls/` |

세 레시피의 추가 native argv는 모두 없음이다. 각 행에서 `job/build/native.{exit,log}`와 `bench.exit`를 확인하고, `build-only-proof/implementation.d`의 private 헤더, `link-evidence.txt`의 같은 `implementation.o`, 두 `.map` 파일의 각 `LOAD`, `expected-libs.sha256`을 대조했다. 두 역할이 실행 가능하고 `runs/`와 `summary.json`이 없었을 때의 로그를 `build-verification.log`에 남겼다. OpenSSL 작업은 이후 재개했으므로, 재개 뒤 생긴 `runs/`는 초기 build-only 증거에 포함되지 않는다. `build-only-proof/`의 맵과 해시는 재개 전 상태다. 링크 증거 자체로는 핸드셰이크나 앱 교환을 판정하지 않는다.

`build-only-proof/candidates.tsv`에 실제 소비 계획별 결과가 있다. OpenSSL의 `libcrypto`·`libssl` 단독 링크는 브리지의 필요한 심볼이 없어 부적합했고 `openssl`이 유효했다. 합성 대조에서는 유효한 두 계획을 자동 선택하지 않았으며, 동일 SDK/인자를 두고 `--resume … --use other`로 고른 계획만 링크했다. 들어오는 직접 링크 인자가 다르면 로더 목록이 같아도 한 계획으로 합치지 않는다. 혼합/해석 불가 링크 실패와 바뀐 사설 SDK는 중단한다(`E/review/after/build-plan-green.log`).

## 3. 정상 시나리오 판정표

최종 격리 실행에서 OpenSSL 20개 조합이 모두 통과했다. 본 시도의 실패·미지원·증거 부족은 각각 0건이다. 두 역할의 실제 라이브러리 해시가 실행 전후 일치했다. 아래 근거는 **J**(`R/matrix/openssl/job`) 기준이다. 비교군과 통제 시도는 합산하지 않았다.

`server`는 서버 인증, `mtls`는 상호 인증이며, 계측 역할을 바꾸면 다른 연결을 시작한다. **성공/요청은 본 시도만** 센다. doctor는 해당 시나리오를 한 번 전부 실행하며, 통과한 조합은 별도 예열 한 번과 본 시도 두 번을 갖는다.

| 인증 | 시나리오 | 계측 역할 | 성공/요청 | 판정 | 근거 디렉터리 |
|---|---|---|---:|---|---|
| 서버 | S0 | 클라이언트 | 2/2 | 통과 | `runs/server-S0-client/` |
| 서버 | S0 | 서버 | 2/2 | 통과 | `runs/server-S0-server/` |
| 서버 | S1 | 클라이언트 | 2/2 | 통과 | `runs/server-S1-client/` |
| 서버 | S1 | 서버 | 2/2 | 통과 | `runs/server-S1-server/` |
| 서버 | S2 | 클라이언트 | 2/2 | 통과 | `runs/server-S2-client/` |
| 서버 | S2 | 서버 | 2/2 | 통과 | `runs/server-S2-server/` |
| 서버 | S3 | 클라이언트 | 2/2 | 통과 | `runs/server-S3-client/` |
| 서버 | S3 | 서버 | 2/2 | 통과 | `runs/server-S3-server/` |
| 서버 | S4 | 클라이언트 | 2/2 | 통과 | `runs/server-S4-client/` |
| 서버 | S4 | 서버 | 2/2 | 통과 | `runs/server-S4-server/` |
| mTLS | S0 | 클라이언트 | 2/2 | 통과 | `runs/mtls-S0-client/` |
| mTLS | S0 | 서버 | 2/2 | 통과 | `runs/mtls-S0-server/` |
| mTLS | S1 | 클라이언트 | 2/2 | 통과 | `runs/mtls-S1-client/` |
| mTLS | S1 | 서버 | 2/2 | 통과 | `runs/mtls-S1-server/` |
| mTLS | S2 | 클라이언트 | 2/2 | 통과 | `runs/mtls-S2-client/` |
| mTLS | S2 | 서버 | 2/2 | 통과 | `runs/mtls-S2-server/` |
| mTLS | S3 | 클라이언트 | 2/2 | 통과 | `runs/mtls-S3-client/` |
| mTLS | S3 | 서버 | 2/2 | 통과 | `runs/mtls-S3-server/` |
| mTLS | S4 | 클라이언트 | 2/2 | 통과 | `runs/mtls-S4-client/` |
| mTLS | S4 | 서버 | 2/2 | 통과 | `runs/mtls-S4-server/` |

판정은 `passed`(필수 증거가 두 본 시도에 있음), `unsupported`(어느 역할이 TLS 작업 미지원을 명시), `failed`(실제 작업 실패 또는 관측값이 계약과 모순), `insufficient_evidence`(성공한 작업을 입증할 필수 관측이 누락되거나 불완전)로 나눈다. 빌드만 검증한 wolfSSL·GnuTLS의 다섯 시나리오는 미검증이다. 이는 해당 구현의 S2 또는 S4 미지원 판정이 아니다. CF의 암호문 도달처럼 이 계측층에서 식별할 수 없는 개별 연구 지표는 별도로 표시한다.

## 4. 연결별 원자료와 해석

`R/index/{cases,connections}.tsv`에서 조합·단계·목적·UUID·포트·PID·훅 행수·앱 길이·원자료 경로를 확인한다. [대조 스크립트](../tools/validation/index-matrix.sh)로 서로 다른 **80 UUID**(doctor 20, 예열 20, 본 시도 40), 양쪽 실제 실행 파일·라이브러리 지도, 상대역 훅/PMU 배제, 방향별 원래 앱 입력과 받은 바이트를 대조했다. 80개 모두 양 역할이 TLS 1.3을 협상했고 세션을 재개하지 않았다. 서버 인증과 mTLS 각각에 맞는 인증서 검증도 확인했다. 앱 기록은 TLS 암호문 복호화 추정으로 만든 것이 아니다. 이 표에서 `attempt`와 `trace`는 `J=R/matrix/openssl/job` 기준 상대 경로다.

```sh
J="$R/matrix/openssl/job"
jq -r '.cases[] | [.auth, .scenario, .role, .benchmark.verified_samples, .state] | @tsv' \
  "$J/summary.json"
case_dir="$J/runs/server-S0-client/benchmark"
id=$(jq -er '.attempts[1].connection_id' "$case_dir/result/analysis.json")
head -n 4 "$case_dir/events/$id.client.csv"
jq '{connection_id,run_id,purpose,pid,argv,binary_sha256,exit,prepared_start}' \
  "$case_dir/result/attempt-2/attempt.json"
wc -c "$case_dir/result/attempt-2/"*.stdin "$case_dir/result/attempt-2/"*.stdout
```

이 머신의 발행 검산도 통과했다. 양쪽 지도 **160개**의 완료 표시와 앞 행 수(마지막 개행 포함), 대상 CSV **80개**의 생산/실제 행 수·방향별 행 수·첫/끝 사건 이름·바이트·단조 ns·차를 동일 UUID의 `summary.json`과 대조했다. `2^53 ns` 경계에서 실제 끝−시작 `1001 ns`를 `1000 ns`로 반올림하지 않는 회귀를 별도로 확인했다(`E/ultragoal/repair/exact-ns-{red,green}.log`). `E/ultragoal/final-publication-audit.log`와 `final-runtime-audit.json`은 이 실행의 검산 기록이다.

보관 뒤 다시 검산하려면 아래 명령을 실행한다. 검산기는 bubblewrap 안에서만 당시 경로를 복원하고, 원본 발행 해시와 연결별 원자료를 다시 대조한다. 검산 출력은 임시 공간에 쓴다. **보관소를 가린 독립 빌드·실행에는 필요하지 않다.** 서명이나 적대적 변조 인증도 아니다.

```sh
sh "$HOME/.local/share/turtle/archive/2026-11-26/verify.sh"
```

`summary.json`의 조합별 `doctor.evidence` 및 `benchmark.evidence`에서 `connection_id`로 조인한다. `attempt_directory` 아래에 컨트롤러 `attempt.json`, 각 역할의 `*.ndjson`, 앱 `*.stdin`·`*.stdout`, `*.stderr`가 있다. 동일 단계의 `events/<UUID>.<role>.maps`는 종료 직전에 얻은 지도다. 원래 `/proc` 행에 완료 표시 `# turtle-maps rows=N`을 붙여 잘린 자료를 경로 불일치와 구분한다. 계측 역할에만 `events/<UUID>.<role>.csv`와 같은 이름의 `.csv.count`가 있다. `.count`는 헤더를 제외한 생산기 콜백 행 수와 마지막 개행이다. 헤더가 옳고 양방향 훅이 남아 있어도 행 하나가 통째로 사라지면 증거 부족으로 판정한다.

준비 중 찍은 `attempt.json`의 `images`와 종료 직전 지도는 별개 시점이다. 집계의 `prepared_images`는 준비 자료를 PID·실행 파일 경로/해시·선택 DSO 해시와 대조했다(160/160 일치). 실제 모순은 실패, 형식 불량 또는 어느 이미지가 불안정한지 확정할 수 없으면 증거 부족, 일반적인 준비 자료 부재는 보조 자료 `unavailable`로 남긴다. 준비 자료는 필수인 종료 직전 지도를 대신하지 않는다. `result/manifest.json`의 profile에는 양 역할 명령, 인증, 앱 데이터가 있으며 해당 연결의 앱 검증 값은 `application.messages`에 남는다.

### S0: 준비에서 정리까지

| 단계 | 소유 경로 | 사건·기록 |
|---|---|---|
| 예약·기동 | [`Job::phase`](../src/submission/job.cpp)의 controller profile → [`perform`](../src/native/stream.cpp)의 포트/연결 ID와 역할 프로세스 기동 | `doctor/profile.json`, `benchmark/profile.json`, `attempt.json`의 `purpose`, `run_id`, `connection_id`, `pid`, `port`, `argv`; doctor 내부 이름이 `sample`이어도 본 시도에 합산하지 않음 |
| TCP 연결·TLS 준비 | [`role.cpp`](../src/submission/role.cpp)의 `connect_socket`, `turtle_tls_setup`, 대상만 `turtle_tls_set_hooks` | `ready`, 준비 중 `images`, `prepared_start`의 release와 양쪽 시작 증거. [`Scenario::run`](../src/native/endpoint.cpp)이 `turtle_wait_start`를 통과하기 전까지 TLS 핸드셰이크를 시작하지 않음 |
| 세션과 관측 | `Scenario::handshake` → `turtle_tls_connect`/ `turtle_tls_accept`; [OpenSSL 브리지](examples/submissions/openssl/implementation.cpp)의 실제 세션·BIO 기록 | 양 역할 `hs_begin`, `hs_complete`; 대상의 `before_send_offer`는 쓰기 요청량, `after_recv`는 양수 읽기 반환값. 실제 TLS 1.3, 재개/클라이언트 early data 없음 및 검증 사실은 `application.sessions`. 상대는 앱·세션 기록만 제공 |
| 종료·정리 | `Scenario::run` → capture/detach → TLS 및 소켓 정리 → 컨트롤러 회수 | 양쪽 `end`, 종료 0, 네 앱 스트림 모두 0바이트, 같은 UUID의 사설 DSO 지도와 단측 훅. 컨트롤러의 `attempt.json`과 각 역할 stderr는 실패도 보존 |

### S1–S4: 앱 단계와 암호문 경계를 섞지 않음

- **S1:** `CAD=ping`(4바이트, `70696e67`)을 클라이언트가 보냈고 서버가 전량 검증한다. 서버 응답은 0바이트다. 서버 계측에서는 완료한 서버 핸드셰이크와 CAD 전량 앱 읽기 사이의 마지막 `after_recv`를 `cad_receive_boundary.candidate`에 남긴다. 그 호출 하나가 보호된 CAD 레코드 하나였다고 주장하지 않는다.
- **S2/S4:** `SAD1=helo`(4바이트, `68656c6f`)를 사전 인사 경로로 보내고 클라이언트가 전량 대조했다. 서버 계측에서는 SF·CF의 **TLS 메시지 콜백**과 SAD₁ 실제 쓰기 요청/수락을 순서대로 잇는다. 클라이언트 계측 본 시도 8/8에서는 로컬 Finished 메시지 콜백 뒤에 SAD₁ 전량 앱 읽기가 관측됐다. 이는 TLS 콜백과 앱 사건의 순서다. 정상 표본의 보호된 CF/SAD₁ 소켓 송신·도달 순서와 서버 CF 암호문 도착은 `null`(관측 불가)이며 인사 쓰기 수락으로 대신하지 않는다. 별도의 CF 보류 대조는 동작을 뒷받침하지만 정상 표본의 순서를 소급 입증하지 않는다.
- **S3/S4:** 본 시도 16/16에서 서버의 `handshake_complete`와 `cad_validated`가 **각각** 같은 서버의 `first_sad2_write`보다 앞섰다(`application.server_response_gate`). `SAD2=pong`(4바이트, `706f6e67`)은 S4의 인사와 다른 내용이다. 수신 `first_read_return`과 `full_read_return`은 구분한다. 한 호출로 전량을 읽으면 같은 시각이 가능하지만, 내용 검증 `validated`는 별도 사건이다.

### 최종 연결 두 건의 원자료 예

시각은 각 계측 역할의 `CLOCK_MONOTONIC` ns다. 훅 구간은 모든 앱 교환이나 핸드셰이크 시간을 뜻하지 않는다.

| 조합 · 연결 UUID | 첫 암호문 훅 | 끝 암호문 훅 | 차(ns) · 훅 수(송신/수신) | J 기준 원자료 |
|---|---|---|---|---|
| S0 서버 인증·클라이언트 계측 · `5dfd32af-121a-4336-b5fe-13ca2c9b3458` | `before_send_offer` 1,493 B · `19865156745928` | `before_send_offer` 80 B · `19865157759228` | `1013300` · 2/12 | `runs/server-S0-client/benchmark/{events/<UUID>.client.csv,result/attempt-2/}` |
| S4 mTLS·서버 계측 · `22e7badb-e67e-40c0-8dc8-af8f7ed11913` | `after_recv` 5 B · `19886126774532` | `before_send_offer` 26 B · `19886168376633` | `41602101` · 3/12 | `runs/mtls-S4-server/benchmark/{events/<UUID>.server.csv,result/attempt-2/}` |

- S0 예에서 클라이언트 앱 층의 `hs_begin` `19865156526528` → `hs_complete` `19865157910328`의 차는 `1383800 ns`다. 양 역할 종료 0, 네 앱 스트림 모두 0 B다. 이 앱 구간에서 클라이언트 PMU는 `3320080` CPU cycle을 기록했다.
- S4 예에서 **같은 서버 앱 시계**의 `hs_complete` `19886128437232`와 `CAD.validated` `19886168334233`가 모두 `SAD2.write_attempt` `19886168355633`보다 앞선다. 상대 클라이언트 앱은 SAD₂ 4 B를 한 번에 읽어 첫/전량 수신이 모두 `19886168457933`이고, 뒤에 별도의 내용 검증 `19886168479433`을 남겼다.

**PMU의 cycle 값은 본 시도 40/40에서 가용, 논문용 성능 적격 표본은 0/40이다.** native SDK의 성능 자격이 요구하는 전송 훅 관측 범위를 확인하지 못했다(`transport_hook_unconfirmed`). 제출 경로의 단측 CSV 검증과 SDK 성능 자격은 다른 판정이다. 이 수치로 구현별·시나리오별 성능 차이를 추정하지 않는다.

## 5. 통제 시험과 정리 전후

### 정상 표본과 섞지 않은 통제

| 통제 | 기대와 판정 방법 | 원자료 |
|---|---|---|
| 인증 실패 및 복구, S0 서버 인증·클라이언트 계측 | **통제 통과.** 첫 시도만 다른 CA를 주입했다. 클라이언트는 `hs_begin` 뒤 인증서 검증에서 실패했고, 같은 컨트롤러 실행에서 다음 새 연결은 성공했다. 교환 성공 1/2, 예상 컨트롤러 종료 1, 통제 스크립트 종료 0이다. 양 시도의 역할 PID 네 개를 회수했고 두 포트에 LISTEN이 남지 않았다. | `R/controls/handshake-failure/{controller.exit,cleanup.log,result/analysis.json,result/attempt-1/client.stderr,result/attempt-2/attempt.json}` |
| CF 보류, 서버 인증 및 mTLS | **2/2 통과.** 양 역할 링크 맵의 같은 브리지 객체와 사설 DSO 해시를 확인한 별도 프로그램에서 새 소켓 쌍을 열었다. mTLS에서는 Certificate/CertificateVerify를 먼저 넘겼다. 두 인증 모두 CF만 74 B 보류한 동안 클라이언트가 SAD₁ 15 B(`turtle-greeting`) 전량을 검증했고, CF 전달 뒤 서버 accept를 마쳤다. 이 인사는 정상 S2/S4의 4 B 시험 입력과 다르다. | `R/controls/openssl-greeting-control/{server.log,mtls.log,server.exit,mtls.exit,client-bridge-object.log,server-bridge-object.log,private-libraries.log,control-identities.sha256}` |

별도 [대조 실행기](../tools/validation/runtime-controls.sh)는 두 통제의 상태를 각각 남기며 정상 80개 연결에 하나도 합산하지 않는다. 통제의 의도한 인증 실패는 기능 미지원으로 세지 않는다.

### 전후 및 미결

| 증거 묶음 | 확인한 결과 / 제한 |
|---|---|
| 정리 전 `E/before/` | 빌드 회귀 3/3, 제출물 빌드 3/3. OpenSSL 20조합·40본의 앱 교환·지도·단측 훅은 대조했으나, 구형 롤업은 실제 TLS 세션/인증과 시나리오 경계의 증거 확인을 필수로 하지 않아 이 성공 건수를 엄격 동작 통과로 승격하지 않았다. `runtime-controls-current/handshake-failure.exit=1`: 통제의 실제 실패→성공 및 정리는 확인했으나 실패 이유가 구형 브리지 stderr에 없었다. CF 보류 통제는 두 인증에서 확인했다. |
| 개발 증거 `E/checked/`와 첫 격리 `A/home/TURTLE-validation-replay-20261126/` | 정상 20/20·40/40 및 두 통제 확인. 첫 격리에서는 빌드 3/3+3/3도 확인. 독립 리뷰에서 TLS 작업과 사후 관측 유실 판정의 분리, 준비 이미지 모순 및 지도 읽기·완료 여부를 추가 검증하도록 지적했다. |
| 후속 격리 `A/home/TURTLE-ultragoal-replay-20261126/`, `A/home/TURTLE-ultragoal-verified-20261126/` | 두 스냅샷에서 정상 20/20·40/40을 확인했으나, 별도 의도적 대조에서 각각 CSV의 행 경계 잘림과 높은 단조 시각에서 검산기의 반올림을 재현했다. 정상 표본에서 자료 유실이나 오판이 확인됐다는 뜻은 아니다. 두 스냅샷 및 초기 격리 결과는 최종 판정에 합산하지 않는다. |
| 최종 소스 `R/` | 최종 manifest 일치, 계약 3/3·독립 빌드 3/3·정상 20/20 및 40/40·통제 통과. `verification.txt`는 `scenario=0 index=0 controls=0`, 별도 발행 검산과 소스가 일치하는 리뷰도 통과했다. |

동일 동결 소스의 전체 CTest는 **35/35**, 정적 분석은 8개 번역 단위에서 진단 0건(`E/ultragoal/qa-final-verified/`). 설치한 SDK와 기본 빌드의 벤더 독립성도 통과했다(`E/ultragoal/sdk-final-verified/independence.log`). 독립 코드 리뷰는 **APPROVE**, 구조 리뷰는 **CLEAR**다(`E/ultragoal/final-review/{receipt.json,code.md,architecture.md}`). 비차단 후속 항목은 외부에서 바꾼 JSON 보조 개수 필드에서 정수에 아주 가까운 소수의 표기를 더 엄격히 거절하는 것과, 파일 읽기 실패 원인을 단계별로 더 자세히 남기는 것이다. 두 항목 모두 생산 CSV·행 수·정밀 시각 대조나 TLS 교환 판정을 대신하지 않는다.

### 레거시와 파일 보존

| 후보 | 현재 진입점과 제거 시 영향 | 처분 |
|---|---|---|
| [SDK 프로필·역할 어댑터](endpoint.md)와 [reference 역할](../tools/reference/CMakeLists.txt) | [`bench.sh`](../bench.sh)의 `PROFILE.json`, `--client`, `--server`와 `turtle run`의 프로필 경로. 외부 SDK 소비자·설치 예·`endpoint_installed_tls_matrix` 및 invalid-request 회귀가 쓴다. 기본 제출 빌드는 reference를 끄고 이 경로로 폴백하지 않는다. | **유지.** 제출 경로의 벤더 독립성과 기존 SDK 계약을 각각 검증한다. |
| `turtle-pair`와 기존 원자료 재판독 | `bench.sh --pair`의 진단 실행, `turtle analyze`의 보관 결과 판독. `pair_diagnostics`, `native_packet_replay`와 기존 자료 비교에 영향을 준다. | **유지.** 진단·재판독을 삭제하면 증거 재확인 수단을 잃는다. |
| 빌드 연구의 별도 링크·선택 대조 | 역사 실험 내부 스크립트로만 호출되며, 현재 공개 빌드 진입점은 `bench.sh --build-only`다. 새 회귀가 실사용 후보 대조를 검증한다. | **통합.** 필수 동작과 입력은 [합성 레시피](../tests/fixtures/submission-recipe.sh)·[계약 회귀](../tests/submission-build-contract.sh)·[검증 드라이버](../tools/validation/build-matrix.sh)로 옮겼다. 이전 실행 코드를 새 제품의 두 번째 링커로 이관하지 않았다. |
| 옛 `build/`, `outputs/`, `out/` | 당시 연구의 링크 3개는 `out/endpoint-peer-build/libturtle_observe.so.1`을 참조한다. 현행 제출물은 사용하지 않는다. | **제품 트리에서 정리.** 옛 `out/`은 `A/workspace/out/`에 보존했다. `sh "$A/read-legacy-observer.sh"`로 옛 링크 세 개를 읽기 전용으로 검사한다. [현행 CLI](../README.md#build-and-run-a-submission)는 기본 빌드와 결과를 작업 트리 밖에 쓴다. |
| `.vs`, `.deps`의 로컬 생성물 | `.vs`는 IDE 상태다. `.deps`의 캐시·도구·설치본 경로는 현재 빌드 안내와 연구·논문 자료에서 쓴다. | **별도 보관.** `.vs`는 `A/workspace/vs`로 보관했다. `.deps/{cache,host-tools,prepared}`의 실제 파일은 `~/.local/share/turtle/workspaces/TURTLE/deps/`로 옮기고 세 경로에 링크를 남겼다. |

- 최종 변경은 TLS 반환값을 사후 증거 수집과 분리한다. 수집한 `.partial` 파일과 역할 stderr는 진단용이며 정식 CSV/지도 대신 합격에 쓰지 않는다. [역할 실행·집계 회귀](../tests/submission-capture-failure.sh)는 훅 누락·용량 초과·분리 오류·CSV/지도 쓰기 오류를 증거 부족으로, 초기 훅 설치 오류와 명시적 미지원을 별도 상태로 확인한다. 실제 TLS 지도 대조 7건은 양 역할 종료 0을 유지하되, 읽기/형식 오류나 행 단위 잘림은 증거 부족, 끝까지 읽은 경로 모순은 실패로 구분했다(`E/ultragoal/repair/map-seal-integration.log`). 준비 이미지 대조는 기존 수집 기록을 재사용한다. 관련 RED/GREEN과 정적 분석은 `E/ultragoal/repair/`에 있다. 일곱 함수 ABI와 외부 TLS 원본은 변경하지 않았다.
- `main`의 기존 미커밋 작업과 제출 원본을 보존했다. 동결본은 작업 트리의 실행 소스이며 커밋 하나를 새로 체크아웃한 것이 아니다. **planning-with-files**로 작업 전 인계와 해시를 대조하고 이전 계획·작업일지를 보존했다. **ultragoal**에서는 G005의 CSV 완료 증거를 후속 G006으로, 이후 발견한 정수 검산 문제를 G007-ns로 해결하고 최종 격리 실행으로 검증했다. 리뷰 보류 이력은 로컬 `.omx/ultragoal/ledger.jsonl`(Git 배포본에는 미포함)에 남겼다. 변경 직전·직후에는 **ai-slop-cleaner**로 동작을 고정하고 회귀 검사를 수행했고, 범위 결정과 최종 동결 뒤 **code-reviewer + architect**가 따로 검토했다. 적용 시점은 `E/ultragoal/skill-timing.md`, 수리 근거는 `E/ultragoal/repair/`다.
- [이관·복원 상세](build-study-migration.ko.md). `E/backup/{research.tar,historical-jobs.tar,SHA256SUMS,verified.txt}`는 두 작업 폴더 밖에 있고, 소스 대조와 해시 검산·기존 대조 로그 및 연결 TSV의 실제 읽기를 확인했다. **검증 당시** `E/ultragoal/inventory/counts.txt` 기준 Git 무시 파일 100,199→16,680(83,519개 정리, 새 무시 파일 0), 미추적 파일 40→60이었다. 이후의 보관 경로와 복원 방법은 `A/README.ko.md`에 있다. 연구 원본은 `A/home/TURTLE-build-study/`에 있고 `~/TURTLE-paper`는 그대로다.
- 교환 동작의 통과는 **성능 비교, TCP 전송 순서, 보안 감사, PQ 그룹 협상**을 증명하지 않는다. 간격을 비교할 때는 같은 역할과 관측 층, 두 끝 사건에 한정한다. 다른 호스트의 PMU 가용성이나 정확한 ns 값의 재현을 합격 조건으로 삼지 않는다.
