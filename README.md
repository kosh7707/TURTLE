# TURTLE

**TLS 1.3 전체 핸드셰이크를 같은 실행 계약과 관측 경계에서 비교하는 C++20 벤치마크 프레임워크입니다.** TURTLE은 약어가 아닙니다.

암호군은 `TLS_AES_128_GCM_SHA256` 하나로 고정합니다. 키 교환 그룹과 인증서·서명 방식은 별도 프로필 항목입니다. 실제 인증서 기반 전체 핸드셰이크와 암호화된 핑퐁을 실행하며, PSK·세션 재개·0-RTT는 사용하지 않습니다.

## 1. 무엇을 재는가

TLS 구현체가 메시지 생성, 인증서 검증과 암호 연산을 맡고, 프레임워크가 새 역할 프로세스, TCP, 비차단 실행, 계측과 원자료 저장을 맡습니다. 클라이언트와 서버를 따로 보고하며 해독과 통계는 측정 뒤 별도 프로그램에서 수행합니다.

주 측정 구간은 다음과 같습니다.

| 역할 | 시작 | 끝 |
|---|---|---|
| 클라이언트 `primary_window` | 첫 핸드셰이크 호출 시작 | 전체 퐁 수신 호출 완료 |
| 서버 `primary_window` | 첫 성공 수신 반환 | 전체 퐁 송신 호출 완료 |

보고서는 두 주 구간을 바꾸지 않고 공통 호출 경계, ClientHello→Finished 송신 경계와 레코드 연산 귀속도 추가로 계산합니다. 이 보기는 **어느 I/O 경계 사이에서 작업했는지**를 보여 줄 뿐 메시지의 독립 비용이나 순수 암호 연산 시간을 뜻하지 않습니다. 정확한 경계와 포함 범위는 [실행과 계측 경계](docs/runtime.md)와 [보고서의 측정 구간](docs/reporting.md)에 있습니다.

표본마다 서버와 클라이언트를 새 프로세스로 만들고, 한 역할 프로세스 안에서는 준비 연결 뒤 여러 측정 연결을 차례로 실행할 수 있습니다. 측정 연결은 순서별로 분리해 같은 위치끼리 요약합니다. 연결 셋업과 TCP 연결 시간은 주 구간 밖에 둡니다.

## 2. 어디까지 보이는가

| 항목 | 관측 범위 |
|---|---|
| 경과·CPU 시간 | 단조 시계와 해당 역할 스레드의 CPU 시간입니다. 상대 엔드포인트 대기는 경과 시간에 들어갈 수 있지만 현재 역할의 CPU 연산은 아닙니다. |
| 사이클·명령어 | 지원되는 환경에서 `perf_event_open`으로 같은 역할 스레드를 셉니다. 기본 `user`와 명시적 `user+kernel`을 구별하며 하이퍼바이저·다른 스레드는 제외합니다. 미지원·누락·다중화는 0이 아닌 별도 상태입니다. |
| 힙 | 메모리 모드에서 라이브러리 할당 훅이 본 요청 바이트의 현재값과 구간 최고값입니다. 전체 프로세스 RSS나 스택이 아닙니다. |
| 바이트·I/O | 콜백 경로에서 성공한 송수신의 TLS 스트림과 함수 경계를 기록합니다. TCP/IP 패킷 경계가 아닙니다. 라이브러리 직접 소켓 경로에서는 보이지 않는 값을 0으로 만들지 않습니다. |
| 커널 수신 시각 | 콜백 `recvmsg`의 `SO_TIMESTAMPNS` 부가정보입니다. 각 바이트의 정확한 도착 시각이나 송신·NIC 시각이 아닙니다. |
| 레코드·메시지 | 키 로그와 스트림으로 레코드를 해독하고 메시지 종류와 레코드 범위를 붙입니다. 암호문과 평문의 위치를 혼동하지 않습니다. |
| 라이브러리 평문 알림 | 추적 모드에서 어댑터가 제공할 때 남기는 **시각 없는 메시지 대조 기준**입니다. 종류·순서 대조용이며 메시지 시간이나 비용을 만들 수 없습니다. |

`measurement.channel_observer=false`는 콜백 채널의 관측 함수 포인터만 끕니다. 같은 TLS 콜백 전송 경로, 호출·대기 계측, 키 로그·평문 알림과 성능 카운터 경로는 남으므로 무계측 실행이 아닙니다. 켬/끔 차이는 관측자 유무에 따른 진단값일 뿐 **전체 계측 비용의 수학적 상한이나 하한이 아닙니다**.

OpenSSL 라이브러리 직접 소켓 경로는 TLS 기능을 확인할 수 있지만 프레임워크 스트림과 I/O 분해가 없습니다. 라이브러리 직접 소켓을 쓰는 서버는 첫 수신 경계를 볼 수 없어 `primary_window`를 만들 수 없습니다. 이 프로젝트에는 서버의 계측 없는 외부 기준선이 없습니다.

원자료 형식은 `schema=1`, 현재 측정 의미는 `measurement_contract_revision=2`, 모듈 바이너리 계약은 adapter ABI 2입니다. 세 값은 서로 다른 호환성 축입니다. 자세한 필드와 미계측 표시는 [원자료 형식](docs/record-format.md)을 따릅니다.

## 3. 어떻게 실행하는가

Linux, C++20 컴파일러, CMake 3.20 이상, Ninja와 OpenSSL 개발 파일이 필요합니다. 시험·실험 스크립트에는 Python 3.10 이상과 `openssl` 명령이 필요합니다. 정상 실행 중에는 인터넷을 사용하지 않습니다.

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

기본값은 지휘·클라이언트·서버를 서로 다른 것으로 확인한 물리 코어에 고정하는 것입니다. 해당 배치가 불가능한 개발 환경에서만 `--no-affinity`를 명시합니다. 프로그램은 전역 주파수 정책, Turbo나 `perf_event_paranoid`를 바꾸지 않습니다. 출력 폴더의 기존 표본은 덮어쓰지 않으므로 다시 실행할 때 새 폴더를 지정합니다. 빠른 확인에서는 기본 1,000개 대신 `--samples`를 명시하십시오.

준비 연결과 여러 측정 연결은 `--warmups 1 --connections 2`처럼 지정합니다. 메모리 계측은 `--mode memory`, 상호 인증은 `--mutual-auth`를 사용합니다.

### 한 컨텍스트 안의 반복 보기

기본 보고서는 연결 위치별 진단을 그대로 유지합니다. 같은 역할 프로세스와 TLS 컨텍스트에서 실행한 측정 연결들의 대표값을 별도로 보려면 현재 소스로 `build/turtle-report`를 다시 빌드한 뒤 opt-in 플래그를 사용합니다.

```sh
./build/turtle-report results/study results/study/report --repeated-context
```

이 호출은 기존 보고 파일을 바꾸지 않고 `repeated-context-summary.json`을 하나 더 만듭니다. 각 표본·역할의 측정 연결 `K`개에서 StQ2를 먼저 계산하고, 같은 것으로 확인한 study·batch·실행 조건 안에서 그 컨텍스트 대표값의 분포를 만듭니다. 첫 측정 연결도 원자료와 계산 입력에 남으며 자동으로 버리지 않습니다. 다만 순위 가중치가 0일 수 있습니다. 준비 연결을 두지 않는 `warmups=0`을 권장합니다.

다음 프로필은 `connections=16`, `warmups=0`, `timeout_ms=30000`인 **작은 pilot 예시**입니다. 이 값이 정상상태, 독립성 또는 논문용 표본 충분성을 보장하지 않습니다.

```sh
# 같은 라이브러리 self-pair의 실행별 기술통계
python3 scripts/run-study.py --build build --pki pki/default \
  --profile examples/profiles/repeated-context.json \
  --samples 10 --batches 3 --warmups 0 --modes timing \
  --repeated-context \
  --output results/repeated-context-self

# 상대 엔드포인트를 고정할 수 있는 cross-pair 비교 후보도 생성
python3 scripts/run-study.py --build build --pki pki/default \
  --profile examples/profiles/repeated-context.json \
  --libraries openssl,mbedtls --cross --auth server \
  --samples 10 --batches 3 --warmups 0 --modes timing \
  --repeated-context \
  --output results/repeated-context-cross
```

실행기에 `--connections N`을 쓰면 그 값만 `turtle run`에 전달합니다. 생략하면 프로필 값이나 `turtle`의 기본값 1을 덮어쓰지 않습니다. 반복 보기의 비교는 전체 실행 coverage와 지표 완결성, 하나로 확인된 study 이름공간을 요구하며, 배치별 탐색 결과만 냅니다. 자세한 단위와 지원 경계는 [보고서와 비교 조건](docs/reporting.md)을 확인하십시오.

현재 검증 환경의 소켓 권한 제약 때문에 이 새 프로필의 실제 TCP 다중 연결 실행은 확인하지 못했습니다. 기존의 비소켓 기준 시험 반복은 새 실제 TLS 실행이나 논문용 성능 결론의 근거가 아닙니다.

### 세 라이브러리 빌드

```sh
# 이 단계에서만 공식 배포 소스를 내려받습니다. 전역 설치가 아닙니다.
JOBS=4 scripts/build-deps.sh all
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DTURTLE_WITH_WOLFSSL=ON -DTURTLE_WITH_MBEDTLS=ON
cmake --build build --parallel 4

./build/turtle run --client wolfssl --server mbedtls \
  --pki pki/default --mutual-auth --samples 10 --output results/cross
```

고정 판은 OpenSSL 3.5.4, wolfSSL 5.8.2-stable, Mbed TLS 3.6.4입니다. 의존성 스크립트는 SHA-256 또는 커밋을 확인하며 운영체제 패키지를 설치하지 않습니다. adapter ABI 2의 진입점은 `turtle_adapter_v2`입니다. v1 모듈을 읽는 호환 계층이 없으므로 코어와 모든 어댑터를 함께 다시 빌드해야 합니다. 세 구현의 정확한 지원 범위는 [공통 어댑터 설명](implementations/common/README.md)을 확인하십시오.

### 반복 시험과 연구 실행

```sh
REPEAT=1 scripts/check.sh
REPEAT=20 scripts/check.sh
scripts/static-check.sh build "$PWD" all

python3 scripts/run-study.py --build build --pki pki/default \
  --samples 10 --batches 3 --cross --output results/study
```

시험 반복은 기능 검증이지 논문용 성능 표본이 아닙니다. 보존한 검증 결과와 실패 이력은 [검증 기록](docs/validation.md)에만 모읍니다.

### 고정한 조회·netem 보조 경로

`scripts/netem-study.py`는 합성 인증서 조회 또는 조회를 끈 순수 TLS를 소유한 사용자·네트워크 이름공간에서 실행할 수 있습니다. 조회 결과는 캐시에 실제 소비하지만 수정하지 않은 TLS의 Certificate 메시지나 인증서 입력을 대체하지 않습니다. 이 경로는 인증서 압축·생략·캐싱 기법의 구현이 아닙니다.

```sh
python3 scripts/netem-study.py run --build build --profile PROFILE.json \
  --net-profile NET.json --samples 8 --output RESULTS
```

이 보조 경로는 현재 [모의 CA와 격리 netem 실행](docs/mock-ca.md)에 적힌 범위로 고정했습니다. 기존 손실 조건을 확장하거나 새 네트워크 실험을 이번 목표에 추가하지 않습니다.

## 4. 무엇을 지원하지 않는가

- 한 호스트 안의 로컬 TCP만 실행합니다. 원격 두 호스트 실행기나 호스트 사이 하드웨어 비교는 없습니다.
- 서버의 계측 없는 외부 기준선이 없으며, 관측자 켬/끔 차이로 전체 계측 비용을 복원하지 않습니다.
- 스택 최고 사용량, 커널 송신 시각, NIC 하드웨어 시각, eBPF와 일반 패킷 캡처를 제공하지 않습니다.
- 실제 인증서 압축·생략·캐싱 연구 기법, OCSP/ACME 운영 서비스와 원 논문 재현은 구현하지 않았습니다.
- 강건성·공격·잘못된 인증서 거절·타이밍 누출·보안 성질 증명은 연구 범위가 아닙니다.
- WSL의 기능·구조 진단값을 물리 Linux의 성능 순위나 논문 결론으로 쓰지 않습니다.

현재 상태와 별도 결정이 필요한 범위는 [구현 상태](docs/PROGRESS.md), 주장 가능한 범위는 [논문 메모](docs/paper-notes.md)에 정리했습니다.

## 문서 안내

- [구조와 코드 읽기 순서](docs/architecture.md), [어댑터 작성 안내](docs/adapter-guide.md)
- [실행과 계측 경계](docs/runtime.md), [원자료 형식](docs/record-format.md), [보고서와 비교 조건](docs/reporting.md)
- [구현 결정](docs/DECISIONS.md), [검증 기록](docs/validation.md)
- [최초 인계 문서](docs/design-history.md)는 현재 구현 설명이 아니라 설계 이력입니다.

시험 인증서와 개인키, TLS 키 로그는 실험용입니다. 원자료에는 통신을 해독할 수 있는 비밀값이 있으므로 실제 서비스의 키나 트래픽을 사용하지 마십시오. TURTLE 자체의 배포 라이선스는 아직 정하지 않았습니다. 포함한 외부 코드의 라이선스는 `third_party/`에 보존합니다.
