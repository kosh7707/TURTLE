# TURTLE

**TLS 1.3 전체 핸드셰이크를 같은 실행 계약과 관측 경계에서 비교하는 C++20 벤치마크 프레임워크입니다.** TURTLE은 약어가 아닙니다.

비교 암호군은 `TLS_AES_128_GCM_SHA256` 하나로 고정합니다. 키 교환 그룹과 인증서·서명 방식은 암호군과 별개인 프로필 항목입니다.

구현체는 TLS 메시지 생성·인증서 검증·암호 연산을 맡습니다. 프레임워크는 새 역할 프로세스, TCP, 비차단 실행, 계측, 반복과 원자료 저장을 맡습니다. 클라이언트와 서버를 따로 보고하며, 해독과 통계는 측정이 끝난 뒤 별도 프로그램에서 수행합니다.

강건성, 공격, 잘못된 인증서 거절, 보안 성질 증명은 연구 범위가 아닙니다. 정상적인 인증서 기반 전체 핸드셰이크와 암호화된 핑퐁만 실행합니다. PSK·세션 재개·0-RTT는 사용하지 않습니다.

## 빠르게 실행하기

Linux, C++20 컴파일러, CMake 3.20 이상, Ninja, OpenSSL 개발 파일이 필요합니다. 테스트·실험 스크립트에는 Python 3.10 이상과 `openssl` 명령이 필요합니다. 실행 중에는 인터넷을 사용하지 않습니다.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 4
scripts/make-pki.sh pki/default

./build/turtle capabilities
./build/turtle run --client openssl --server openssl \
  --profile examples/profiles/server-auth.json --samples 10 \
  --output results/first

./build/turtle-interpret results/first/sample-000001/client.jsonl \
  results/first/sample-000001/client.decoded.json
./build/turtle-report results/first results/first/report
```

기본값은 서로 다른 물리 코어 세 개에 지휘·클라이언트·서버를 고정하는 것입니다. 그런 코어 배치가 불가능한 개발 환경에서만 `--no-affinity`를 명시합니다. 전역 주파수 정책·Turbo·권한 설정을 프로그램이 바꾸지는 않습니다. 확인하지 못한 조건은 경고로 남습니다.

출력 폴더에 이미 같은 표본 번호가 있으면 덮어쓰지 않습니다. 다시 실행할 때는 새 폴더를 지정합니다. 기본 `--samples`는 1,000이므로 빠른 확인에는 위와 같이 횟수를 지정합니다. 메모리 측정은 `--mode memory`, 상호 인증은 `--mutual-auth`를 추가합니다.

표본 안에서 준비 연결과 여러 측정 연결을 차례로 실행하려면 `--warmups 1 --connections 2`처럼 지정합니다. 측정 연결 수의 기본값은 1이며, 여러 연결의 결과는 순서별로 분리해 요약합니다. TCP 버퍼 요청값과 실제 적용값도 원자료에서 구별합니다.

## 세 라이브러리를 함께 빌드하기

```sh
# 여기서만 공식 배포 소스를 내려받습니다. 전역 설치가 아닙니다.
JOBS=4 scripts/build-deps.sh all
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DTURTLE_WITH_WOLFSSL=ON -DTURTLE_WITH_MBEDTLS=ON
cmake --build build --parallel 4
```

고정 판은 OpenSSL 3.5.4, wolfSSL 5.8.2-stable, Mbed TLS 3.6.4입니다. OpenSSL·Mbed TLS 압축 파일의 SHA-256과 wolfSSL 커밋을 확인합니다. 기본 캐시는 `.deps/`이며 `TURTLE_DEPS_ROOT`로 바꿀 수 있습니다. OpenSSL만 사용할 때는 시스템의 3.0 이상도 지원하지만 원자료에 실제 판을 기록합니다. 기본 코어 실행 파일은 TLS 라이브러리에 링크하지 않고 각 역할에서 어댑터를 불러옵니다.

의존성 빌드에는 C 컴파일러, `curl`, Git, Perl, Make와 `tar`도 필요합니다. 이 스크립트는 운영체제 패키지를 자동 설치하지 않습니다.

세 라이브러리의 공통 프로필은 AES-128-GCM/SHA-256, P-256 키 교환, ECDSA P-256 인증서, 호환용 ChangeCipherSpec, 티켓 0장입니다. 지원 범위를 벗어난 설정은 조용히 무시하지 않습니다. 상세한 차이는 [어댑터 지원 범위](implementations/common/README.md)에 있습니다.

```sh
./build/turtle run --client wolfssl --server mbedtls \
  --pki pki/default --mutual-auth --samples 10 --output results/cross
```

## 원자료에서 무엇을 볼 수 있는가

| 항목 | 의미 |
|---|---|
| 시간 | 단조 시계와 해당 역할 스레드의 CPU 시간입니다. |
| 사이클·명령어 | 가능한 환경에서 `perf_event_open`으로 해당 스레드의 사용자 공간 실행을 셉니다. 미지원·누락·다중화는 구별합니다. |
| 힙 | 별도 메모리 모드에서 라이브러리 할당 훅이 관측한 요청 바이트의 현재값·구간 최고값을 기록합니다. 전체 프로세스 RSS나 스택이 아닙니다. |
| 바이트 | 실제 성공한 송수신의 방향별 TLS 스트림입니다. TCP/IP 패킷 경계나 크기가 아닙니다. |
| 커널 수신 시각 | `recvmsg`의 `SO_TIMESTAMPNS` 부가정보를 별도로 남깁니다. 각 바이트의 정확한 도착 시각으로 확대 해석하지 않습니다. |
| 메시지 | 키 로그와 스트림에서 레코드를 해독하여 종류와 레코드 범위를 붙입니다. 암호문 오프셋과 평문 메시지 오프셋을 혼동하지 않습니다. |
| 요약 | 역할별 연산·입출력·대기·틈의 합, StQ 세 값, 전체 표본, 분포 SVG와 독립 부트스트랩 비교 후보를 남깁니다. |

주 측정 구간은 다음과 같습니다.

- **클라이언트:** 첫 핸드셰이크 호출 시작부터 퐁 수신 호출 완료까지입니다.
- **서버:** 첫 성공한 수신 반환부터 퐁 송신 호출 완료까지입니다.
- 셋업·연결 열기·닫기는 별도 경계로 남기며, TCP 연결 시간은 주 구간에 넣지 않습니다.
- 세션 티켓을 켜면 이 구간 안에서 수행된 티켓 작업도 들어갑니다. 티켓 0장과 2장은 같은 프로필이 아닙니다. `examples/profiles/openssl-tickets.json`으로 그 차이를 관측할 수 있습니다.

**송수신 함수 경계의 관측이 모든 TLS 메시지의 독립적인 연산 시간을 뜻하지는 않습니다.** 한 호출이 여러 레코드나 메시지를 처리하면 그 묶음까지가 관측 가능한 범위입니다. 계측과 키 로그·바이트 복사의 비용도 실제 실행에 영향을 줍니다. 원자료와 보정 표본을 보존하지만, 이를 빼면 비계측 실행의 참값이 된다고 주장하지 않습니다.

## 테스트와 반복 실험

```sh
# 소스와 테스트의 빌드 폴더를 분리합니다. 설치된 의존성만 사용합니다.
REPEAT=1 scripts/check.sh             # 빠른 통합 확인
REPEAT=20 scripts/check.sh            # 각 시험 20회 반복
scripts/static-check.sh build "$PWD" all  # 설치된 cppcheck + clang-tidy

# 묶음마다 순서를 섞고, 모든 시도를 기록합니다. --cross는 모든 역할 조합입니다.
python3 scripts/run-study.py --build build --pki pki/default \
  --samples 10 --batches 3 --cross --output results/study
```

자동 시험의 실제 연결은 로컬 TCP입니다. 모의 구현 시험과 실제 TLS 시험을 분리하고, 서버 인증·상호 인증, 시간·메모리 실행, 방향별 바이트 일치, 해독, 구간 합과 원자료 재계산을 확인합니다. 테스트 반복은 기능 검증이며 논문용 성능 표본이 아닙니다. WSL에서 개발 중 다른 작업과 함께 얻은 수치를 최종 성능 결론으로 쓰지 않습니다.

## 지원하지 않는 것과 인계 문서

스택 최고 사용량, 커널 송신·NIC 시각, eBPF·패킷 캡처, 독립 두 어댑터 간 계측 영향 검증은 아직 제공하지 않습니다. 기본 해독기는 AES-128-GCM/SHA-256을 지원합니다. 원자료 없이 성능 수치를 추정하지 않습니다. 컨텍스트 전달 계약은 있지만 현재 세 TLS 어댑터의 저장 결과는 비어 있습니다. 다른 기법의 구현이나 모의 CA가 이미 완성됐다는 뜻도 아닙니다.

- [구조와 소유권](docs/architecture.md), [어댑터 작성 안내](docs/adapter-guide.md)
- [원자료 형식](docs/record-format.md), [실행과 계측 경계](docs/runtime.md)
- [대체 측정 구간과 같은 상대 구현의 비교](docs/reporting.md)
- [진행 상태와 남은 범위](docs/PROGRESS.md), [검증 기록](docs/validation.md)
- [구현 결정](docs/DECISIONS.md), [논문에 사용할 수 있는 주장 범위](docs/paper-notes.md)
- [최초 인계 문서 — 현재 구현 설명이 아닌 설계 이력](docs/design-history.md)

시험 인증서와 개인키, TLS 키 로그는 실험용입니다. 원자료에는 통신을 해독할 수 있는 비밀값이 있으므로 실제 서비스의 키나 트래픽을 사용하지 않습니다. TURTLE 자체의 배포 라이선스는 아직 정하지 않았습니다. 포함한 외부 코드의 라이선스는 `third_party/`에 보존합니다.
