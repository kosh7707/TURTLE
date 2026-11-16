# TURTLE

TURTLE은 TLS 1.3의 논리 메시지를 프레임워크가 순서대로 실행하는 C/C++ 연구 프레임워크입니다. TURTLE은 약어가 아닙니다. 실제 인증서 기반 전체 핸드셰이크와 암호화된 응용 교환을 실행하며, 클라이언트와 서버의 비용을 각각 기록합니다.

구현체는 메시지 조립·처리와 레코드 암복호화를 제공합니다. 프레임워크가 상태 전환, 버퍼, 레코드 분할·묶음, 출력 배치, 소켓과 계측을 소유합니다. OpenSSL·Mbed TLS·wolfSSL의 고정 소스에 내부 경계를 분리하는 패치를 적용합니다. 전체 핸드셰이크 API를 호출하는 어댑터나 동적 모듈 로더는 없습니다.

## 빌드와 실행

Linux, C++20 컴파일러, CMake 3.20 이상, Ninja, Python 3.12 이상, Perl, Make와 시험 인증서 생성용 `openssl` 명령이 필요합니다. 현재 검증 장비는 x86_64 WSL2입니다. ML-KEM 최적화 비교는 x86_64 AVX2 지원 장비에서 검증했습니다.

```sh
# 기본은 네트워크를 사용하지 않습니다. 고정 배포본과 git 객체 캐시가 필요합니다.
scripts/build-deps.sh
scripts/build.sh
scripts/make-pki.sh pki/default

python3 scripts/run.py --output results/first
python3 scripts/report.py results/first results/first/report
```

의존성 캐시 기본 경로는 `.deps`, 새로 패치하고 빌드한 의존성 경로는 `.deps-message`입니다. 처음 캐시를 준비할 때만 `scripts/build-deps.sh --fetch`를 사용합니다. 내려받을 버전·해시·커밋은 [dependencies.py](scripts/dependencies.py)에 고정했습니다. 기존에 수정한 소스 트리를 빌드 입력으로 삼지 않고 배포본 또는 해당 git 객체에서 추출합니다. 패치가 바뀌면 별도의 빈 `--deps` 디렉터리에서 재생성합니다. 시스템 패키지를 설치하지 않습니다.

`scripts/build.sh 'openssl;mbedtls;wolfssl'`처럼 필요한 구현체만 고를 수 있습니다. 기본은 세 라이브러리, ML-KEM 두 구현, BiTHaC 두 구현과 ClientHello 교체 예제입니다. `TURTLE_BUILD_DIR`, `TURTLE_DEPS_ROOT`, `JOBS`로 경로와 병렬 빌드 수를 지정합니다. 구현체마다 `turtle-구현체-client`와 `turtle-구현체-server` 실행 파일을 만듭니다.

기본 실행은 `client-request`, black-box, 서버 인증, 프로세스당 컨텍스트 하나·측정 연결 하나·준비 연결 0개입니다. `run.py`는 로컬의 독립 프로세스를 시작하는 작은 연구용 실행 도구입니다. 엔드포인트 자체는 자기 실행 명세 JSON 하나만 받으며 웹이나 범용 CLI 제품은 제공하지 않습니다.

```sh
python3 scripts/run.py --client wolfssl --server mbedtls --mutual-auth \
  --scenario finished-ping --depth white-box --records bundle \
  --send server-hello-first --stream --allocations --output results/detail
```

자세한 필드와 직접 실행법은 [실행·사건 계약](docs/analysis/record-format.md), 새 구현체 등록과 한 함수 교체는 [구현자 안내](docs/design/implementation-guide.md)를 따릅니다. 출력 디렉터리는 덮어쓰지 않습니다.

## 비교 범위

| 시나리오 | 실행 |
|---|---|
| `handshake` | 인증서 기반 전체 핸드셰이크 |
| `server-ping` | 서버 Finished 배치를 제출한 뒤 Ping, 클라이언트 Pong |
| `finished-ping` | 서버 Finished 레코드와 Ping 레코드를 같은 출력 배치로 제출 |
| `client-request` | 핸드셰이크 후 클라이언트 요청, 서버 응답 |

암호군은 `TLS_AES_128_GCM_SHA256`, 인증서는 P-256 ECDSA로 고정합니다. 기본 키 교환은 P-256이며 ML-KEM 구현은 `ML-KEM-768`을 사용합니다. 재개·PSK·0-RTT·세션 티켓은 사용하지 않습니다. Black-box와 white-box는 같은 메시지 실행기를 사용합니다. 양쪽 모두 시나리오 진입부터 자기 역할의 마지막 필수 송신 제출·처리·검증 완료까지 측정하며 서버의 첫 소켓 읽기 대기도 포함합니다. 상대의 완료까지 기다리는 제어 확인은 측정 구간 밖입니다.

ML-KEM, BiTHaC, 합성 객체 MockCA, 소유 네임스페이스의 netem, pcap·커널 사건과 별도 perf 표본 실행을 제공합니다. [연구 실행 안내](docs/experiments/research.md)를 참고하십시오. 관측하지 않은 값과 실제 0을 구별하며 CPU 표본 비중을 정확한 함수 호출 시간으로 바꾸지 않습니다.

## 검증과 문서

```sh
cmake -S tests -B build-message-tests -G Ninja -DTURTLE_SOURCE_BUILD="$PWD/build-message"
cmake --build build-message-tests
ctest --test-dir build-message-tests --output-on-failure
python3 scripts/static-check.py --build build-message
```

시험 빌드는 소스 빌드와 분리되어 있습니다. 시험 중에는 다운로드하지 않습니다. 실제 검증 결과·환경 제약은 [검증 기록](docs/project/validation.md)에 모았습니다.

- [프레임워크 설계](docs/design/architecture.md): 실행 계약, 소유권, 보호 단계, 역할별 완료, 버퍼·비용·자료 모델
- [다음 설계 논의](docs/design/discussion.md): 비교 조건, 확장 경계, 비용 해석, 자료 계약, 버퍼 전략
- [구현자 안내](docs/design/implementation-guide.md)
- [실행·사건 계약](docs/analysis/record-format.md), [보고서와 통계](docs/analysis/reporting.md)
- [네트워크 관측](docs/analysis/network.md), [CPU 표본](docs/analysis/cpu-profiling.md)
- [구현 계획](docs/project/implementation-plan.md), [설계 결정](docs/project/DECISIONS.md)
- [작업 공간과 자료 보존](docs/project/workspace.md)

활성 빌드는 `build-message/`와 `build-message-tests/`입니다. 과거 빌드의 원자료·검증 근거는 `artifacts/build-history/2026-11-16/`으로 정리했으며 `results/`의 실행 자료는 유지했습니다. 재생성 가능한 구형 빌드 산출물은 제거했습니다. 당시 자료 안의 경로·해시는 수정하지 않고 이동 원장으로 보존 위치를 설명합니다. 새 도구는 `turtle-message-…/1` 계약만 읽으며 구형 자료·설정·보고서의 판독기, 변환기와 별칭을 제공하지 않습니다. 시험용 개인키와 평문 캡처는 실제 서비스에 사용하지 않습니다. 외부 코드의 라이선스는 원본 의존성과 `third_party/`에 보존합니다.
