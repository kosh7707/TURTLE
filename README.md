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

## 격리 네트워크에서 조회 또는 순수 TLS 실행

작업 트리에는 `synthetic-lookup-plus-standard-tls` 시나리오가 있습니다. 클라이언트가 별도 모의 CA 엔드포인트에서 공개 인증서 PEM 객체를 조회하거나 고정 저장본에서 찾고, 반환 바이트를 미리 보유한 기준 객체와 대조해 캐시에 넣은 뒤에만 표준 TLS 실행을 시작합니다. 조회 결과는 실제로 검사·저장·사용 가능 상태 판정에 소비되지만, stock OpenSSL·wolfSSL·Mbed TLS의 인증서 입력을 대체하지는 않습니다. TLS 어댑터는 계속 정상 인증서 체인을 보내고 검증합니다. 따라서 이 시나리오는 인증서 생략·압축·경량화 구현이나 그 성능 결과가 아닙니다.

같은 runner는 프로필의 `lookup.enabled=false`인 정상 TLS도 실행합니다. 이때 client/server/router 세 network namespace와 두 veth 링크만 만들고, `tls_c2s`·`tls_s2c` 두 방향에만 정책을 적용합니다. C++ 실행에는 client/server namespace만 전달하며 CA namespace, CA 소켓, 조회 원자료를 만들지 않습니다. `lookup.enabled=true`의 기존 네 namespace·네 링크·네 방향 계약은 바뀌지 않았습니다.

격리 실행 도구의 공개 명령은 다음과 같습니다.

```sh
python3 scripts/netem-study.py snapshot --object FILE --output SNAPSHOT.json
python3 scripts/netem-study.py probe --output RESULTS
python3 scripts/netem-study.py run --build build --profile PROFILE.json \
  --net-profile NET.json --samples 8 --output RESULTS
python3 scripts/netem-study.py verify --build build --pki PKI_DIR \
  --output RESULTS --require-supported
```

`run`의 `--samples`는 선택 사항이며 생략하면 프로필의 `measurement.samples`를 씁니다. 별도 `--attempts`나 `--lookup` 옵션은 없습니다. runner는 프로필의 `lookup.enabled`로 두 topology를 고릅니다. `verify`는 기존 합성 조회 고정 묶음만 실행하며 순수 TLS 검증의 별칭이 아닙니다. 프로필·netem 설정 형식, 권한 실패와 결과 해석은 [모의 CA와 격리 netem 실행](docs/mock-ca.md)을 따릅니다.

OpenSSL의 실제 표준 TLS와 netem을 함께 쓴 고정 검증 묶음은 2026년 10월 15일 한 번 실행해 통과했습니다. CA→client 5ms·20% loss의 사전 고정 64 attempts가 모두 성공했고, qdisc skb drop 94와 CA 소켓 `TCP_INFO.total_retrans` 차이 58을 별도로 관측했습니다. 이 수치는 기능 gate 증거이지 성능 표본이나 현실망 모델이 아닙니다. 손실 설정값, 실제 skb drop, TCP 재전송은 서로 다른 값이며 어느 하나로 다른 값을 대신하지 않습니다.

G005의 구현·고정 실행·오프라인 보고를 완료했습니다. 보존한 일곱 조건의 원자료를 최신 보고 도구로 다시 처리한 합계는 requested=started=100, success=97, timeout=3이며 attempt/connection 행도 각각 100개입니다. G006에서는 당시 57×20=1,140회, G007 동결 트리는 58×20=1,160회, M5 CLI 상호운용 트리는 70×20=1,400회, M6 I/O 경로 트리는 72×20=1,440회 통과했습니다. 최종 correctness 수리와 채널 관측자 on/off를 포함한 현재 트리는 73×20=1,460회 통과했고 24개 생산 번역 단위·CLI endpoint의 정적 검사, cleaner와 독립 검토를 마쳤습니다. 다섯 보존 원자료 묶음의 offline 재생도 통과했으며 이전 차단·실패와 수정 근거는 [검증 기록](docs/validation.md)에 별도로 보존합니다.

stock TLS의 Certificate 메시지는 그대로이며 실제 인증서 압축·생략·캐싱 연구 기법은 구현하지 않았습니다. 진단 실행에서 얻은 지연값은 기능 경로 확인용 데이터이며 성능 논문 결론이 아닙니다.

## 세 라이브러리를 함께 빌드하기

```sh
# 여기서만 공식 배포 소스를 내려받습니다. 전역 설치가 아닙니다.
JOBS=4 scripts/build-deps.sh all
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DTURTLE_WITH_WOLFSSL=ON -DTURTLE_WITH_MBEDTLS=ON
cmake --build build --parallel 4
```

고정 판은 OpenSSL 3.5.4, wolfSSL 5.8.2-stable, Mbed TLS 3.6.4입니다. OpenSSL·Mbed TLS 압축 파일의 SHA-256과 wolfSSL 커밋을 확인합니다. 기본 캐시는 `.deps/`이며 `TURTLE_DEPS_ROOT`로 바꿀 수 있습니다. OpenSSL만 사용할 때는 시스템의 3.0 이상도 지원하지만 원자료에 실제 판을 기록합니다. 기본 코어 실행 파일은 TLS 라이브러리에 링크하지 않고 각 역할에서 어댑터를 불러옵니다.

현재 모듈 계약은 adapter ABI 2이며 진입점은 `turtle_adapter_v2`입니다. v1으로 빌드한 기존 `.so`는 새 코어가 `declaration`·`setup` 호출 전에 거절하므로 모든 어댑터를 함께 다시 빌드하십시오. 호환 계층은 없습니다. adapter ABI 2, 측정 계약 개정값 2, 원자료 형식 1은 각각 모듈 바이너리, 측정 귀속, JSON 형식을 구별하는 별개 버전입니다.

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
| 사이클·명령어 | 가능한 환경에서 `perf_event_open`으로 해당 스레드를 셉니다. 기본 `user`는 사용자 공간, 명시적 `user+kernel`은 같은 스레드의 커널 실행까지 포함하며 둘 다 하이퍼바이저·다른 스레드는 제외합니다. 미지원·누락·다중화는 0이 아닌 별도 상태로 남깁니다. |
| 힙 | 별도 메모리 모드에서 라이브러리 할당 훅이 관측한 요청 바이트의 현재값·구간 최고값을 기록합니다. 전체 프로세스 RSS나 스택이 아닙니다. |
| 바이트 | callback I/O에서 실제 성공한 송수신의 방향별 TLS 스트림입니다. TCP/IP 패킷 경계나 크기가 아닙니다. native socket 경로에서는 unavailable이지 관측된 0바이트가 아닙니다. |
| 커널 수신 시각 | callback `recvmsg`의 `SO_TIMESTAMPNS` 부가정보를 별도로 남깁니다. availability는 수집 통로의 지원·설정이며 사건 발생 증거는 실제 원자료 행입니다. 각 바이트의 정확한 도착 시각으로 확대 해석하지 않습니다. |
| 메시지 | 키 로그와 스트림에서 레코드를 해독하여 종류와 레코드 범위를 붙입니다. 암호문 오프셋과 평문 메시지 오프셋을 혼동하지 않습니다. |
| 요약 | 역할별 연산·입출력·대기·틈의 합, StQ 세 값, 전체 표본, 분포 SVG와 독립 부트스트랩 비교 후보를 남깁니다. |

주 측정 구간은 다음과 같습니다.

- **클라이언트:** 첫 핸드셰이크 호출 시작부터 퐁 수신 호출 완료까지입니다.
- **서버:** 첫 성공한 수신 반환부터 퐁 송신 호출 완료까지입니다.
- 셋업·연결 열기·닫기는 별도 경계로 남기며, TCP 연결 시간은 주 구간에 넣지 않습니다.
- 세션 티켓을 켜면 이 구간 안에서 수행된 티켓 작업도 들어갑니다. 티켓 0장과 2장은 같은 프로필이 아닙니다. `examples/profiles/openssl-tickets.json`으로 그 차이를 관측할 수 있습니다.

**송수신 함수 경계의 관측이 모든 TLS 메시지의 독립적인 연산 시간을 뜻하지는 않습니다.** 한 호출이 여러 레코드나 메시지를 처리하면 그 묶음까지가 관측 가능한 범위입니다. 계측과 키 로그·바이트 복사의 비용도 실제 실행에 영향을 줍니다. 원자료와 보정 표본을 보존하지만, 이를 빼면 비계측 실행의 참값이 된다고 주장하지 않습니다.

OpenSSL native socket 정상 경로도 실제 TLS로 확인했습니다. native 클라이언트는 호출 경과·스레드 CPU를 남기지만 I/O 분해와 framework stream은 없고, native 서버의 첫 수신 기반 주 구간은 unavailable입니다. 이 결과는 기능 성공과 metric availability를 구별하며 callback/native 자동 성능 비교를 만들지 않습니다. wolfSSL·Mbed TLS native는 지원하지 않습니다. 기존 zero-loss runner에서 두 경로의 receiver-facing router egress skb metadata도 확인했지만, 이는 full pcap·syscall trace·물리 packet 또는 unique TLS byte 비교가 아닙니다.

프로필 JSON에서 `measurement.channel_observer=false`를 지정하면 callback I/O의 관측 함수 포인터만 끕니다. 기본값은 true이며 CLI 옵션은 없습니다. off에서도 같은 TLS callback transport, 호출·대기 계측, keylog/plaintext와 perf 설정을 사용하므로 “무계측 실행”이 아닙니다. stream·I/O·kernel receive 수집은 unavailable로 남기고, 양 역할에서 공통 `handshake_call_begin_to_application_complete` 경과와 가능한 스레드 CPU를 별도 진단값으로 계산합니다. 이 공통값은 observer-off 서버의 unavailable 주 측정 구간을 대체하지 않습니다. 네 batch 교대 실행으로 계산 경로를 확인했지만 on/off 차이의 방향·부호·크기나 유의성, WSL 성능 결론을 합격 기준으로 쓰지 않습니다.

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

수정하지 않은 `/usr/bin/openssl` 3.0.13의 `s_client`·`s_server`와도 공개 어댑터 API만으로 상호운용 시험을 수행했습니다. OpenSSL·wolfSSL·Mbed TLS 각각의 client/server와 서버 인증/상호 인증, 모두 12조건에서 TLS 1.3 인증과 암호화된 양방향 응용 바이트를 확인했습니다. 이 시험은 callback I/O 정상 경로의 기능 근거입니다. 공개 API에 `close_notify` 구동 함수가 없어 EOF 허용 옵션을 명시하므로 TLS shutdown alert의 완전성, native 경로 동등성이나 성능은 증명하지 않습니다.

## 지원하지 않는 것과 인계 문서

스택 최고 사용량, 커널 송신·NIC 시각, eBPF, 독립 두 어댑터 간 계측 영향 검증은 아직 제공하지 않습니다. 격리 netem runner의 AF_PACKET trace는 router veth의 skb 관측이며 일반 패킷 캡처나 물리 wire 관측을 대체하지 않습니다. 기본 해독기는 AES-128-GCM/SHA-256을 지원합니다. 원자료 없이 성능 수치를 추정하지 않습니다. 컨텍스트 전달 계약은 있지만 현재 세 TLS 어댑터의 저장 결과는 비어 있습니다. 합성 조회·모의 CA 기반이 실제 인증서 압축이나 캐싱 기법까지 구현했다는 뜻은 아닙니다.

- [구조와 소유권](docs/architecture.md), [어댑터 작성 안내](docs/adapter-guide.md)
- [모의 CA와 격리 netem 실행](docs/mock-ca.md)
- [원자료 형식](docs/record-format.md), [실행과 계측 경계](docs/runtime.md)
- [대체 측정 구간과 같은 상대 구현의 비교](docs/reporting.md)
- [진행 상태와 남은 범위](docs/PROGRESS.md), [검증 기록](docs/validation.md)
- [구현 결정](docs/DECISIONS.md), [논문에 사용할 수 있는 주장 범위](docs/paper-notes.md)
- [최초 인계 문서 — 현재 구현 설명이 아닌 설계 이력](docs/design-history.md)

시험 인증서와 개인키, TLS 키 로그는 실험용입니다. 원자료에는 통신을 해독할 수 있는 비밀값이 있으므로 실제 서비스의 키나 트래픽을 사용하지 않습니다. TURTLE 자체의 배포 라이선스는 아직 정하지 않았습니다. 포함한 외부 코드의 라이선스는 `third_party/`에 보존합니다.
