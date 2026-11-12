# 빌드와 실행 헬퍼

저장소 루트에서 아래 명령을 사용합니다. 스크립트는 자기 위치로 소스를 찾으므로 다른 작업 폴더에서도 절대 경로로 실행할 수 있습니다. 기본 출력은 저장소 안에 만들며 환경 변수로 지정한 상대 경로는 호출한 작업 폴더 기준입니다.

## 자주 쓰는 명령

```sh
# 의존성을 처음 준비하거나 다시 만드는 단계입니다. 다운로드는 이 단계에서 수행합니다.
JOBS=4 scripts/build-deps.sh all

# 준비된 모듈과 양쪽 엔드포인트·분석·조회 도구를 빌드합니다.
scripts/build.sh

# 별도 시험 빌드와 전체 시험을 한 번 실행합니다.
REPEAT=1 scripts/check.sh

# 정상 TLS 실행에 쓸 로컬 시험용 인증서입니다.
scripts/make-pki.sh pki/default
./build-module/turtle-local --client wolfssl --server mbedtls \
  --pki pki/default --no-affinity --no-perf --output results/local-new
```

`build.sh`는 CMake 구성과 빌드만 수행합니다. 같은 명령을 반복하면 기존 빌드에서 필요한 파일을 갱신합니다. `check.sh`는 같은 빌드 헬퍼를 호출한 다음 CTest·부품 경계·셸 구문·변경 공백을 검사합니다. 기존 반복 기본값은 20회이므로 한 번 확인할 때는 `REPEAT=1`을 지정합니다. `STATIC_CHECKS=1`을 함께 주면 사용 가능한 정적 분석 도구도 실행합니다.

## 빌드 구성

| 명령 | 기본 출력 | 빌드 대상 |
| --- | --- | --- |
| `scripts/build.sh` 또는 `scripts/build.sh module` | `build-module/` | 모듈, 클라이언트·서버, 조회, 보고서·해독 |
| `scripts/build.sh builtin openssl` | `build-builtin-openssl/` | OpenSSL 내장 클라이언트·서버와 로컬 실행기 |
| `scripts/build.sh client wolfssl` | `build-client-wolfssl/` | wolfSSL 내장 클라이언트 |
| `scripts/build.sh server mbedtls` | `build-server-mbedtls/` | Mbed TLS 내장 서버 |
| `scripts/build.sh analysis` | `build-analysis/` | 보고서·해독 도구 |
| `scripts/build.sh tests` | `build-tests-independent/` | 별도 시험 빌드. 시험 실행은 하지 않음 |

내장 구성의 구현체를 생략하면 OpenSSL입니다. 세 기본 라이브러리와 `bithac-baseline`, `bithac-cached`, `mlkem-c`, `mlkem-avx2`를 선택할 수 있습니다. 해당 의존성은 먼저 준비해야 합니다. 클라이언트·서버 전용 구성에는 상대 역할과 분석 도구를 넣지 않습니다.

모듈·시험 구성은 OpenSSL을 켜고 지정한 의존성 폴더에 준비된 wolfSSL·Mbed TLS·BiTHaC·ML-KEM을 추가합니다. 준비 상태로 고른 기본 모듈과 추가 CMake 옵션을 실행 전에 출력합니다. BiTHaC와 ML-KEM은 각 비교 쌍의 두 설치본이 있을 때 켭니다. OpenSSL은 로컬 고정 설치가 없으면 CMake가 찾은 시스템 개발 라이브러리를 사용합니다. 고정 소스와 계측 패치가 필요한 실험에서는 먼저 `build-deps.sh`로 준비하십시오.

## 경로와 추가 설정

| 변수 | 기본값 | 의미 |
| --- | --- | --- |
| `JOBS` | `4` | 빌드·시험 병렬 수 |
| `TURTLE_DEPS_ROOT` | 저장소의 `.deps` | 준비한 의존성 경로 |
| `TURTLE_BUILD_DIR` | 구성별 기본 출력 | 소스 빌드 경로 |
| `TURTLE_TEST_BUILD_DIR` | 저장소의 `build-tests-independent` | `tests` 구성과 CTest 경로 |
| `TURTLE_BUILD_TYPE` | `Release`, 시험은 `Debug` | `build.sh`의 CMake 빌드 종류 |

`check.sh`는 소스 Release·시험 Debug 구성을 사용합니다. 소스와 시험에 같은 출력 폴더를 지정하면 시작 전에 실패합니다. 구현체·툴체인·의존성 경로가 다른 구성에는 서로 다른 빌드 폴더를 사용하십시오.

```sh
TURTLE_BUILD_DIR=/absolute/build-client JOBS=8 scripts/build.sh client wolfssl
TURTLE_TEST_BUILD_DIR=/absolute/build-tests scripts/build.sh tests
TURTLE_BUILD_TYPE=Debug scripts/build.sh builtin openssl

# 추가 CMake -D 옵션은 기본 옵션 뒤에 전달됩니다.
scripts/build.sh module -- -DTURTLE_WITH_BITHAC=OFF -DTURTLE_WITH_MLKEM=OFF
TURTLE_BUILD_DIR=/absolute/cross-client scripts/build.sh client wolfssl -- \
  -DCMAKE_TOOLCHAIN_FILE=/absolute/toolchain.cmake \
  -DTURTLE_DEPS_ROOT=/absolute/target-deps
```

기본 설정과 고급 CMake 설정의 실제 반영 결과는 각 폴더의 `CMakeCache.txt`, `build-manifest.txt`, `compile_commands.json`에서 확인합니다. 자세한 인자는 `scripts/build.sh --help`로 볼 수 있습니다.

## 관련 도구

| 도구 | 역할 |
| --- | --- |
| `build-deps.sh` | 고정 TLS 의존성의 다운로드·빌드·로컬 설치 |
| `build.sh` | 구성별 CMake 빌드 |
| `check.sh` | 빌드 후 회귀 시험·구조 검사 |
| `static-check.sh BUILD SOURCE [auto\|cppcheck\|clang-tidy\|all]` | 기존 컴파일 데이터베이스의 정적 검사 |
| `make-pki.sh PATH` | 로컬 시험용 인증서 생성 |
| `run-local.py` | 독립 클라이언트·서버의 정상 TLS 실행 |
| `reproduce-local.py` | 새 경로의 설치·세 라이브러리·두 연결 방식·네 시나리오 재현 |

실험 프로필과 실행·해독·보고 순서는 [프로젝트 README](../README.md), 이전 정리와 재현 근거는 [로컬 웹·재현 기록](../docs/project/local-web-reproduction.md)을 참고하십시오.
