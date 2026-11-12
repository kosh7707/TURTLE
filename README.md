# TURTLE

로컬 실험 조건 작성과 결과 탐색은 별도 저장소 `~/TURTLE-experiment-web`에서 제공합니다. 웹 실행법, 새 빌드·설치 경로의 재현 절차와 산출물 보관 기록은 [로컬 웹·재현 기록](docs/project/local-web-reproduction.md)을 참고하십시오.

**TLS 1.3 전체 핸드셰이크를 같은 실행 계약과 관측 경계에서 비교하는 C++20 벤치마크 프레임워크입니다.** TURTLE은 약어가 아닙니다.

암호군은 `TLS_AES_128_GCM_SHA256` 하나로 고정합니다. 키 교환 그룹과 인증서·서명 방식은 별도 프로필 항목입니다. 실제 인증서 기반 전체 핸드셰이크와 암호화된 핑퐁을 실행하며, PSK·세션 재개·0-RTT는 사용하지 않습니다.

## 1. 무엇을 재는가

TLS 구현체가 메시지 생성, 인증서 검증과 암호 연산을 맡고, 프레임워크가 각 독립 엔드포인트 안에서 TCP, 비차단 실행, 계측과 원자료 저장을 맡습니다. 클라이언트와 서버를 따로 보고하며 해독과 통계는 측정 뒤 별도 프로그램에서 수행합니다.

주 측정 구간은 다음과 같습니다.

| 역할 | 시작 | 끝 |
|---|---|---|
| 클라이언트 `primary_window` | 첫 핸드셰이크 호출 시작 | 시나리오의 마지막 TLS API 성공 반환 |
| 서버 `primary_window` | 첫 성공 TLS 수신 반환 | 시나리오의 마지막 TLS API 성공 반환 |

현재 개정 4는 순수 핸드셰이크, 서버 Ping, Finished와 Ping 결합, 클라이언트 요청·서버 응답을 구별합니다. 마지막 송신은 TLS API의 성공 반환까지, 마지막 수신은 TLS 검증·복호화를 마쳐 응용 버퍼에 전달한 성공 반환까지입니다. 소켓 정리와 사후 결과 조회는 종료 조건이 아닙니다. 보고서는 공통 호출 경계, ClientHello→Finished 소켓 제출 경계와 레코드 연산 귀속도 추가로 계산합니다. 이 보기는 **어느 I/O 경계 사이에서 작업했는지**를 보여 줄 뿐 메시지의 독립 비용이나 순수 암호 연산 시간을 뜻하지 않습니다. 정확한 경계와 포함 범위는 [실행과 계측 경계](docs/design/runtime.md)와 [보고서의 측정 구간](docs/analysis/reporting.md)에 있습니다.

기본은 엔드포인트 프로세스당 TLS 컨텍스트 하나·준비 연결 0개·측정 연결 1개입니다. 외부 실행기는 독립 표본마다 서버와 클라이언트를 새 프로세스로 만들며, 명시하면 한 컨텍스트에서 여러 연결을 실행할 수 있습니다. 측정 연결은 순서별로 분리해 같은 위치끼리 요약합니다. 시행마다 새 TCP를 만들고 연결 셋업·TCP 시간은 별도 구간으로 남깁니다. 클라이언트 TCP 시작과 연결 준비 시작에서 각각 ClientFinished 소켓 제출까지의 구간도 제공합니다.

## 2. 어디까지 보이는가

| 항목 | 관측 범위 |
|---|---|
| 경과·CPU 시간 | 단조 시계와 해당 역할 스레드의 CPU 시간입니다. 상대 엔드포인트 대기는 경과 시간에 들어갈 수 있지만 현재 역할의 CPU 연산은 아닙니다. |
| 사이클·명령어 | 지원되는 환경에서 `perf_event_open`으로 같은 역할 스레드를 셉니다. 기본 `user`와 명시적 `user+kernel`을 구별하며 하이퍼바이저·다른 스레드는 제외합니다. 미지원·누락·다중화는 0이 아닌 별도 상태입니다. |
| 힙 | 메모리 모드에서 라이브러리 할당 훅이 본 요청 바이트의 현재값과 구간 최고값입니다. 전체 프로세스 RSS나 스택이 아닙니다. |
| 바이트·I/O | 콜백 경로에서 성공한 송수신의 TLS 스트림과 함수 경계를 기록합니다. TCP/IP 패킷 경계가 아닙니다. 라이브러리 직접 소켓 경로에서는 보이지 않는 값을 0으로 만들지 않습니다. |
| 커널 수신 시각 | 콜백 `recvmsg`의 `SO_TIMESTAMPNS` 부가정보입니다. 각 바이트의 정확한 도착 시각이나 송신·NIC 시각이 아닙니다. |
| 커널 송신 시각 | 추적 실행의 `--tx-timestamps`로 스케줄러 진입·소프트웨어 송신·누적 ACK 시각을 수집합니다. 송신 요청의 마지막 바이트 ID이며 세그먼트별 시각은 아닙니다. |
| 손실·재전송 | 선택한 tc/eBPF 경로에서 지정 바이트를 포함한 최초 패킷 제거, netem의 실제 qdisc 제거와 커널 재전송을 각각 기록합니다. 패킷 중첩으로 추정한 재전송량과 구별합니다. |
| CPU 표본 | 별도 `scripts/cpu-profile.py` 실행의 `perf.data`와 함수·모듈 period 비중입니다. 주 스레드의 구간별 표본이며 총 CPU 시간·계수와 구별합니다. |
| 레코드·메시지 | 키 로그와 스트림으로 레코드를 해독하고 메시지 종류와 레코드 범위를 붙입니다. 암호문과 평문의 위치를 혼동하지 않습니다. |
| 라이브러리 평문 알림 | 추적 모드에서 어댑터가 제공할 때 남기는 **시각 없는 메시지 대조 기준**입니다. 종류·순서 대조용이며 메시지 시간이나 비용을 만들 수 없습니다. |

`measurement.channel_observer=false`는 콜백 채널의 관측 함수 포인터만 끕니다. 같은 TLS 콜백 전송 경로, 호출·대기 계측, 키 로그·평문 알림과 성능 카운터 경로는 남으므로 무계측 실행이 아닙니다. 켬/끔 차이는 관측자 유무에 따른 진단값일 뿐 **전체 계측 비용의 수학적 상한이나 하한이 아닙니다**.

OpenSSL 라이브러리 직접 소켓 경로는 TLS 기능을 확인할 수 있지만 프레임워크 스트림과 I/O 분해가 없습니다. 라이브러리 직접 소켓을 쓰는 서버는 첫 수신 경계를 볼 수 없어 `primary_window`를 만들 수 없습니다. 이 프로젝트에는 서버의 계측 없는 외부 기준선이 없습니다.

원자료 형식은 `schema=3`, 현재 측정 의미는 `measurement_contract_revision=4`, 모듈 바이너리 계약은 adapter ABI 3입니다. TLS 판독기는 schema 3의 측정 계약 개정 3·4를 받습니다. 개정 3 자료는 기록된 종료점 그대로 재분석하고 개정 4와 같은 비교 조건으로 합치지 않습니다. 다른 형식은 명시적인 오류로 끝냅니다. 세 값은 서로 다른 호환성 축입니다. 자세한 필드와 미계측 표시는 [원자료 형식](docs/analysis/record-format.md)을 따릅니다.

## 3. 어떻게 실행하는가

Linux, C++20 컴파일러, CMake 3.20 이상과 Ninja가 필요합니다. 기본 내장 OpenSSL 구성에는 OpenSSL 개발 파일이 필요하며, 다른 역할별 구성은 선택한 구현체의 의존성만 요구합니다. 시험·실험 스크립트에는 Python 3.10 이상과 `openssl` 명령이 필요합니다. 정상 실행 중에는 인터넷을 사용하지 않습니다.

자주 쓰는 빌드는 [빌드 헬퍼](scripts/README.md)로 선택합니다. 인자 없이 실행하면 준비된 모듈과 클라이언트·서버·분석·조회 도구를 `build-module`에 빌드합니다. 의존성 다운로드는 별도의 `scripts/build-deps.sh` 단계에서 수행합니다.

```sh
scripts/build.sh                       # 모듈 구성
scripts/build.sh client wolfssl        # 클라이언트 전용
scripts/build.sh server mbedtls        # 서버 전용
scripts/build.sh analysis              # 분석 도구
REPEAT=1 scripts/check.sh               # 빌드 + 별도 시험 빌드 + 전체 시험
```

CMake의 기본 어댑터 연결은 `builtin`이며 OpenSSL 하나를 실행 파일에 연결합니다. 다음 명령은 그 내장 구성을 선택합니다. TLS 라이브러리 자체의 정적·동적 링크는 별도 조건입니다.

```sh
scripts/build.sh builtin openssl
scripts/build.sh analysis
scripts/make-pki.sh pki/default
./build-builtin-openssl/turtle-client capabilities

# 서버 터미널: 자기 파일과 주소만 지정합니다.
./build-builtin-openssl/turtle-server --pki pki/default --listen 127.0.0.1:44330 \
  --control-listen 127.0.0.1:44331 --timeout-ms 60000 \
  --output results/server

# 클라이언트 터미널: 위 서버가 준비된 뒤 실행합니다.
./build-builtin-openssl/turtle-client --pki pki/default --connect 127.0.0.1:44330 \
  --control-connect 127.0.0.1:44331 --timeout-ms 60000 \
  --output results/client

./build-analysis/turtle-interpret results/client/client.jsonl results/client/client.decoded.json
./build-analysis/turtle-interpret results/server/server.jsonl results/server/server.decoded.json
./build-analysis/turtle-report --pair results/client/client.jsonl results/server/server.jsonl results/report
```

서버·클라이언트는 다른 작업 폴더와 장비에서 같은 공유 시나리오로 실행할 수 있습니다. 각 장비에 자기 인증서·키·신뢰 파일을 두고 접근 가능한 IPv4 주소를 지정합니다. 데이터 TCP와 제어 TCP는 별도이며 제어 메시지를 TLS에 넣지 않습니다. 클라이언트가 실행 ID를 만들고 서버와 공유합니다. 서로 다른 시계의 절대 단조 시각을 빼지 않으며 교정되지 않은 교차 장비 시간 관계는 미관측입니다.

연결·준비 모듈은 같은 제어 TCP 연결에서 프로토콜·실행 ID·시나리오를 대조하고, 양쪽 TLS 컨텍스트·버퍼·요청 기능의 준비와 계측 지원 상태를 교환합니다. 준비된 뒤 첫 측정용 TLS TCP를 만듭니다. 사전 TLS 핸드셰이크나 확인용 데이터 연결은 만들지 않습니다. `client.jsonl`·`server.jsonl`의 `preparation`과 보고서의 표본별 `preparation`에서 진행 단계와 양쪽 상태를 확인할 수 있습니다. 제어 접속 성공은 데이터 포트 접근이나 인증서 검증 성공을 뜻하지 않습니다. 그 결과는 실제 연결 기록에 남습니다.

로컬 주소도 실제 TCP/IP 소켓을 사용합니다. `127.0.0.1`은 커널 루프백으로 전달되며 물리 NIC를 거치지 않습니다. 서버의 `--listen 0.0.0.0:44330 --control-listen 0.0.0.0:44331`은 모든 로컬 IPv4 인터페이스에서 수신한다는 뜻입니다. 클라이언트에는 `127.0.0.1`이나 서버의 실제 주소를 지정하며 `0.0.0.0`을 접속 대상으로 받지 않습니다. veth 실험은 가상 인터페이스를 지나는 TCP입니다. 같은 호스트의 LAN IP를 지정하는 것만으로 물리 NIC 통과가 보장되지 않습니다. [로컬 TCP·관측 제어와 `s_time`의 차이](docs/design/runtime.md#로컬-tcp와-물리-네트워크)를 참고하십시오.

### 역할별 빌드와 로컬 반복

```sh
scripts/build.sh client wolfssl
scripts/build.sh server mbedtls
scripts/build.sh analysis

# 역할별로 빌드한 wolfSSL 클라이언트·Mbed TLS 서버를 두 번 실행합니다.
python3 scripts/run-local.py --build build-analysis \
  --client-bin build-client-wolfssl/turtle-client \
  --server-bin build-server-mbedtls/turtle-server --pki pki/default \
  --no-affinity --no-perf --samples 2 --output results/local
./build-analysis/turtle-report results/local results/local/report
```

각 빌드에 `CMAKE_TOOLCHAIN_FILE`, `CMAKE_PREFIX_PATH`, `TURTLE_DEPS_ROOT`를 따로 지정할 수 있습니다. 클라이언트 전용 구성은 서버·분석 의존성을 요구하지 않습니다. 교차 컴파일 configure에서 대상 프로그램을 실행하지 않으며 지원 검사는 대상 장비 준비 단계에서 수행합니다. ARM 빌드·실행은 아직 검증하지 않았습니다.

배포할 때는 해당 실행 파일과 자기 인증서·키를 옮깁니다. 동적 TLS 라이브러리로 빌드했다면 그 라이브러리도 대상 로더가 찾을 수 있어야 합니다. 설치 경로는 `CMAKE_INSTALL_RPATH` 또는 대상의 라이브러리 검색 경로로 지정합니다. `cmake --install BUILD --prefix DEST`는 선택한 엔드포인트 실행 파일을 설치합니다.

엔드포인트의 `--cpu N`은 자기 CPU 하나만 선택합니다. 로컬 실행기는 실행기·클라이언트·서버를 서로 다른 것으로 확인한 물리 코어에 배치하며 조회를 켜면 하나를 더 요구합니다. 해당 로컬 배치가 불가능할 때 `--no-affinity`를 명시합니다. 출력은 덮어쓰지 않으며 전역 주파수·Turbo·perf 설정을 바꾸지 않습니다.

프로필은 `scenario`(공유 TLS·연결 수·시간 제한), `endpoint`(자기 파일·계측·소켓), `experiment`(외부 표본 반복·배치)로 나뉩니다. `examples/profiles/`는 `turtle-experiment-profile` schema 1이고 `turtle-local`에 전달합니다. 직접 실행용 `examples/endpoints/`는 `turtle-endpoint-profile` schema 1입니다. 기존 지휘 실행 명령과 평면 프로필의 호환 경로는 제거했습니다. TLS 판독기는 schema 3의 측정 계약 개정 3·4를 받습니다. 개정 3 자료는 기록된 종료점 그대로 재분석하고 개정 4와 같은 비교 조건으로 합치지 않습니다. 다른 형식은 명시적인 오류로 끝냅니다.

준비·측정 연결은 `--warmups 1 --connections 2`, 메모리는 `--mode memory`, 상호 인증은 `--mutual-auth`로 선택합니다. 기본 외부 표본 수는 1입니다.

### 한 컨텍스트 안의 반복 보기

기본 보고서는 연결 위치별 진단을 그대로 유지합니다. 같은 역할 프로세스와 TLS 컨텍스트에서 실행한 측정 연결들의 대표값을 별도로 보려면 현재 소스로 `build-module/turtle-report`를 다시 빌드한 뒤 opt-in 플래그를 사용합니다.

```sh
./build-module/turtle-report results/study results/study/report --repeated-context
```

이 호출은 기존 보고 파일을 바꾸지 않고 `repeated-context-summary.json`을 하나 더 만듭니다. 각 표본·역할의 측정 연결 `K`개에서 StQ2를 먼저 계산하고, 같은 것으로 확인한 study·batch·실행 조건 안에서 그 컨텍스트 대표값의 분포를 만듭니다. 첫 측정 연결도 원자료와 계산 입력에 남으며 자동으로 버리지 않습니다. 다만 순위 가중치가 0일 수 있습니다. 준비 연결을 두지 않는 `warmups=0`을 권장합니다.

다음 프로필은 `connections=16`, `warmups=0`, `timeout_ms=30000`인 **작은 pilot 예시**입니다. 이 값이 정상상태, 독립성 또는 논문용 표본 충분성을 보장하지 않습니다.

```sh
# 같은 라이브러리 self-pair의 실행별 기술통계
python3 scripts/run-study.py --build build-module --pki pki/default \
  --profile examples/profiles/repeated-context.json \
  --samples 10 --batches 3 --warmups 0 --modes timing \
  --repeated-context \
  --output results/repeated-context-self

# 상대 엔드포인트를 고정할 수 있는 cross-pair 비교 후보도 생성
python3 scripts/run-study.py --build build-module --pki pki/default \
  --profile examples/profiles/repeated-context.json \
  --libraries openssl,mbedtls --cross --auth server \
  --samples 10 --batches 3 --warmups 0 --modes timing \
  --repeated-context \
  --output results/repeated-context-cross
```

실행기에 `--connections N`을 쓰면 그 값만 `turtle-local`에 전달합니다. 생략하면 프로필 값이나 `turtle-local`의 기본값 1을 덮어쓰지 않습니다. 반복 보기의 비교는 전체 실행 coverage와 지표 완결성, 하나로 확인된 study 이름공간을 요구하며, 배치별 탐색 결과만 냅니다. 자세한 단위와 지원 경계는 [보고서와 비교 조건](docs/analysis/reporting.md)을 확인하십시오.

현재 WSL에서는 실제 TCP 다중 연결과 세 라이브러리의 네 시나리오를 확인했습니다. 이 기능 검증은 네이티브 Linux의 성능 결론이 아닙니다.

### 세 라이브러리 빌드

```sh
# 이 단계에서만 공식 배포 소스를 내려받습니다. 전역 설치가 아닙니다.
JOBS=4 scripts/build-deps.sh all
scripts/build.sh module

./build-module/turtle-local --client wolfssl --server mbedtls \
  --pki pki/default --mutual-auth --samples 10 --output results/cross
```

`module` 실행 파일은 `--module adapters/openssl.so`처럼 모듈을 명시합니다. `turtle-local --client wolfssl --server mbedtls`는 각 실행 파일에 해당 모듈 경로를 전달합니다. 내장 실행 파일은 `--module`을 받지 않습니다. 혼합 실행은 `--client-bin`, `--server-bin`으로 각 빌드의 실행 파일을 지정합니다.

고정 판은 OpenSSL 3.5.4, wolfSSL 5.8.2-stable, Mbed TLS 3.6.4입니다. 의존성 스크립트는 SHA-256 또는 커밋을 확인하며 운영체제 패키지를 설치하지 않습니다. adapter ABI 3의 진입점은 `turtle_adapter_v3`입니다. v1·v2 모듈을 읽는 호환 계층이 없으므로 코어와 모든 어댑터를 함께 다시 빌드해야 합니다. 세 구현의 정확한 지원 범위는 [공통 어댑터 설명](implementations/common/README.md)을 확인하십시오.

### 반복 시험과 연구 실행

```sh
REPEAT=1 scripts/check.sh
REPEAT=20 scripts/check.sh
scripts/static-check.sh build-module "$PWD" all

python3 scripts/run-study.py --build build-module --pki pki/default \
  --samples 10 --batches 3 --cross --output results/study
```

시험 반복은 기능 검증이지 논문용 성능 표본이 아닙니다. 보존한 검증 결과와 실패 이력은 [검증 기록](docs/project/validation.md)에만 모읍니다.

### 고정한 조회·netem 보조 경로

`scripts/netem-study.py`는 합성 인증서 조회 또는 조회를 끈 순수 TLS를 소유한 사용자·네트워크 이름공간에서 실행할 수 있습니다. 조회 결과는 캐시에 실제 소비하지만 수정하지 않은 TLS의 Certificate 메시지나 인증서 입력을 대체하지 않습니다. 이 경로는 인증서 압축·생략·캐싱 기법의 구현이 아닙니다.

```sh
python3 scripts/netem-study.py run --build build-module --profile PROFILE.json \
  --net-profile NET.json --samples 8 --output RESULTS
```

기존 조회 경로는 [모의 CA와 격리 netem 실행](docs/experiments/mock-ca.md)을 따릅니다. 원본 패킷 보존, [TCP 바이트 분석](docs/analysis/tcp-analysis.md), 방향별 속도·초기 혼잡 윈도를 지원합니다. `examples/networks/tls-1mbit-cwnd4.json`은 네트워크 프로필 schema 3 예시입니다. 네트워크 프로필도 현재 형식만 받습니다.

네트워크 schema 3은 지정 위치의 최초 패킷 제거와 커널 재전송·qdisc 제거 수집을 추가합니다. 이 선택 경로에는 관리자 권한, Clang BPF target, 커널 BTF와 libbpf가 필요합니다. `scripts/kernel-loss-study.py`로 세 라이브러리의 무손실·지정 손실·랜덤 손실 복구를 검증합니다. [빌드·실행 절차와 관측 한계](docs/analysis/tcp-analysis.md#지정-바이트-손실과-커널-재전송)를 따릅니다.

### 새 프로토타입과 논문 기법

`--scenario handshake|server-ping|finished-ping|client-request`, `--send-policy native|server-hello-first`, `--client-bytes`, `--server-bytes`로 실행을 선택합니다. 상세 내부 구간은 `--mode trace`에서 기록합니다. 라이브러리별 실제 관측 위치와 차이는 [프로토타입 계약](docs/design/prototype.md)에 있습니다.

`JOBS=4 scripts/build-bithac.sh`와 `-DTURTLE_WITH_BITHAC=ON`으로 저자 코드의 기준/캐시 쌍을 추가합니다. `scripts/bithac-study.py`는 첫 연결의 캐시 준비와 이후 재사용을 구별해 시간·추적·메모리 자료와 표를 만듭니다. [출처와 재현 절차](docs/experiments/research-reproduction.md)를 따릅니다.

`JOBS=4 scripts/build-mlkem.sh`와 `-DTURTLE_WITH_MLKEM=ON`으로 같은 wolfSSL 기반의 `mlkem-c`·`mlkem-avx2` 쌍을 추가합니다. 실제 C/AVX2 분기를 추적하고 ML-KEM 이외의 라이브러리 오브젝트가 같은지 검사합니다. [비교 조건과 재생성 절차](docs/experiments/mlkem-comparison.md)를 따릅니다. ARM 최적화 쌍은 아직 없습니다.

CPU 함수·모듈 표본은 [CPU 프로파일링](docs/analysis/cpu-profiling.md)의 별도 수집기로 실행합니다. `--cpu-profile` 표지가 있는 원자료는 일반 시간 비교에서 제외하며 실제 수집 증거는 `perf.data`로 보존합니다.

## 4. 무엇을 지원하지 않는가

- 서로 다른 장비에는 실행 중인 서버의 데이터·제어 IP:Port로 접속합니다. 배포·새 프로세스 반복·결과 회수는 외부 실행 환경의 책임이며 SSH 자동화를 필수 기능으로 두지 않습니다. 실제 ARM 장비·툴체인 검증, 네이티브 Linux 본 실험, 배포 크기·RSS 계측은 후속 작업입니다.
- 서버의 계측 없는 외부 기준선이 없으며, 관측자 켬/끔 차이로 전체 계측 비용을 복원하지 않습니다.
- 스택 최고 사용량, NIC 하드웨어 시각과 CPU 호출 스택·코어별 귀속은 미지원입니다. 커널 재전송·소프트웨어 송신·ACK와 원본 pcap의 관측 위치는 구별합니다.
- 저자 BiTHaC의 실제 캐싱 비교 쌍과 upstream ML-KEM C/AVX2 비교를 제공합니다. 인증서 압축, OCSP/ACME 운영 서비스, 후보 AVX-512 논문 구현과 논문 성능 수치의 재현은 아직 제공하지 않습니다.
- 강건성·공격·잘못된 인증서 거절·타이밍 누출·보안 성질 증명은 연구 범위가 아닙니다.
- WSL의 기능·구조 진단값을 물리 Linux의 성능 순위나 논문 결론으로 쓰지 않습니다.

현재 상태와 남은 작업은 [구현 계획](docs/project/implementation-plan.md), 실제 검증 결과와 해석 한계는 [구현 보고서](docs/project/implementation-report.md)에 정리했습니다.

## 문서 안내

- [전체 문서 안내와 읽기 순서](docs/README.md)
- [구조와 코드 읽기 순서](docs/design/architecture.md), [어댑터 작성 안내](docs/design/adapter-guide.md)
- [실행과 계측 경계](docs/design/runtime.md), [원자료 형식](docs/analysis/record-format.md), [보고서와 비교 조건](docs/analysis/reporting.md)
- [구현 결정](docs/project/DECISIONS.md), [검증 기록](docs/project/validation.md)
- [로컬 구현·검증 보고서](docs/project/implementation-report.md)는 실제 TLS·손실 복구·논문 기법 검증 결과와 재생성 명령을 모읍니다.

시험 인증서와 개인키, TLS 키 로그는 실험용입니다. 원자료에는 통신을 해독할 수 있는 비밀값이 있으므로 실제 서비스의 키나 트래픽을 사용하지 마십시오. TURTLE 자체의 배포 라이선스는 아직 정하지 않았습니다. 포함한 외부 코드의 라이선스는 `third_party/`에 보존합니다.
