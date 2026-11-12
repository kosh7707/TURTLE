# 논문 후보와 BiTHaC 재현

2026년 11월 11일 확인한 출처와 수행 범위입니다.

| 후보 | 일차 출처 | 판단 |
|---|---|---|
| Bidirectional TLS Handshake Caching for Constrained Industrial IoT Scenarios | [저자 논문](https://www.spice.rwth-aachen.de/assets/pdf/bodenhausen2025caching.pdf), [저자 BiTHaC 코드](https://github.com/RWTH-SPICe/BiTHaC) | 실제 인증서 캐싱과 바이트 감소를 관측할 수 있어 채택했습니다. |
| Faster Post-Quantum TLS 1.3 Based on ML-KEM: Implementation and Assessment | [논문](https://arxiv.org/abs/2404.13544), [저자 자료](https://zhengjieyu.github.io/) | 논문 판·공개 구현 대응, 동일 기반 비교 쌍과 호출 경로가 아직 고정되지 않아 미채택입니다. |

첫 동일 KEM 비교에는 위 AVX-512 논문 대신 upstream wolfSSL 5.8.2의 ML-KEM-768 C/AVX2 구현 쌍을 고정했습니다. [실제 호출 분기·정상 벡터·비교 조건](mlkem-comparison.md)을 검증했고 이 결과를 해당 후보 논문의 구현 재현으로 표시하지 않습니다. 첫 배치의 논문 기법은 아래 BiTHaC, 구현 최적화는 ML-KEM 쌍, 송신 정책 사례는 세 표준 라이브러리의 `native`/`server-hello-first`입니다.

## 원본과 변경

BiTHaC 커밋은 `68ad825a37ef72cc1db4a67eb6d13275cc61f8aa`입니다. 공개 코드의 `wolfssl/version.h`는 5.7.0입니다. 논문 V절의 일반 구현·대역폭 설명은 5.6.0, V-B 처리시간 실험은 5.7.0을 명시하므로 단순한 버전 불일치로 묶지 않습니다. 이번 결과는 고정한 공개 코드의 TLS 1.3 경로 실행이며 논문의 정확한 바이너리나 성능 수치 재현이라고 부르지 않습니다. [논문 평가 절](https://arxiv.org/html/2508.03321v1#S5)

`scripts/build-bithac.sh`는 같은 커밋·컴파일 조건에서 `bithac-baseline`과 `bithac`을 만듭니다. 차이는 `WOLFSSL_CACHED_INFO`, `WOLFSSL_SSC`이며 저자 `configure.ac`의 `--enable-cached-info`, `--enable-ssc`와 같습니다. 현재 환경에 autotools가 없어 원본 CMake 빌드를 사용했습니다. 기준을 최신 wolfSSL 5.8.2로 바꾸지 않았습니다.

저자 README의 TLS 1.3 제한에 따라 작은 인증서 캐시 사전 검증 최적화와 CertificateRequest 캐싱은 사용하지 않습니다. 캐싱은 TLS PSK 재개와 다르며 매 연결의 CertificateVerify·Finished·인증·새 TCP·응용 교환을 유지합니다. 비표준 확장이므로 원자료는 `scenario_name=research-tls13`, `technique=bithac-tls13`과 원저자 캐시 켬/끔 구분을 남깁니다.

기법 자체는 저자 코드입니다. TURTLE 패치는 처리·레코드·캐시 송신 관측과 서버 Ping 준비 상태를 추가합니다. wolfSSL 5.7.0의 서버 응용 쓰기 조건 변경은 비교 양쪽에 똑같이 적용합니다. 캐시 메시지 형식이나 적중 결정을 TURTLE에서 새로 구현했다고 표시하지 않습니다.

## 상태와 검증

저자 캐시는 라이브러리 내부의 프로세스 전역 상태입니다. 프레임워크 전역 서비스·소유 계측기를 추가하지 않았습니다. 새 역할 프로세스마다 빈 상태에서 시작하고 첫 측정 연결이 채운 뒤 다음 연결이 재사용합니다. 클라이언트 peer ID는 서버 이름으로 고정하며 다른 상대를 섞지 않습니다. 준비 비용은 `warmups=0`인 첫 측정 연결에 남습니다. 힙 계측은 할당 훅을 통과한 요청 바이트이며 저자 코드의 정적 캐시 배열·스택·전체 RSS를 포함하지 않습니다. 이 값만으로 전체 메모리 절감을 주장하지 않습니다.

로컬 시험 PKI를 명시한 원본 `server -i -v 4`, `client -b 2 -v 4`는 성공했고 `artifacts/bithac-upstream-local-pki/`에 명령·로그를 남겼습니다.

두 구현 × 네 시나리오 × 서버/상호 인증의 16개 실행에서 두 연결씩 검증합니다. 첫 연결에는 캐시 송신 사건이 없고, 두 번째에는 실제 `CISSC_SendCachedTls13Certificate` 사건과 짧아진 메시지가 있습니다. 같은 ECDSA 시험 체인에서 클라이언트 Certificate 메시지 871→18바이트, 서버 871→50바이트를 관측했습니다. 전체 TCP/IP 트래픽 감소율과는 다릅니다. 인증과 응용 교환도 별도로 검증합니다.

## 실행·재분석

```sh
JOBS=4 scripts/build-bithac.sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DTURTLE_ADAPTER_LINKAGE=module -DTURTLE_BUILD_MODULES=ON -DTURTLE_WITH_OPENSSL=ON \
  -DTURTLE_WITH_WOLFSSL=ON -DTURTLE_WITH_MBEDTLS=ON -DTURTLE_WITH_BITHAC=ON
cmake --build build --parallel 4
python3 scripts/bithac-study.py run --build build --pki pki/default \
  --samples 3 --connections 2 --no-affinity --output results/bithac-pilot
python3 scripts/bithac-study.py analyze --build build --output results/bithac-pilot
```

시간·추적·메모리를 별도 프로세스 쌍에서 실행하고, 표본마다 두 구현의 순서를 저장한 seed로 섞습니다. 보고서와 `bithac-summary.json`, `bithac-table.csv`를 재생성합니다. 연결별 구간과 모듈 로드→컨텍스트 해제의 경과·스레드 CPU를 남깁니다. 후자는 준비·해제 동기화 대기를 포함하고 프로세스 시작·모듈 해제·최종 기록 출력은 제외합니다.

`artifacts/bithac-pilot-1/`의 3모드 × 3표본 × 2구현 × 2역할 × 2연결은 72행이며 독립 표본 72개가 아닙니다. WSL 기능·구조 자료로서 원저자 성능이나 네이티브 Linux 순위를 주장하지 않습니다.

## 원래 측정과 TURTLE의 대응

논문의 대역폭 실험은 Alpine 3.18.3 컨테이너·tcpdump·가상 Ethernet에서 연결 생성, 방향별 응용 메시지 하나, 연결 종료를 관측합니다. 캐시 준비 연결을 먼저 실행하며 반복 10회의 평균·최솟값·최댓값을 보고합니다. 처리시간 실험은 Raspberry Pi Zero W의 로컬 인터페이스에서 E2E 핸드셰이크 시간 100회의 평균·표준편차입니다. 정확한 시작·끝 API는 본문에서 확인되지 않습니다. 메모리는 Bytehound와 lowresource 빌드의 최대 관측값입니다. [논문 V-A~C](https://arxiv.org/html/2508.03321v1#S5)

공개 예제 `ClientBenchmarkConnections`의 표시 이름 `wolfSSL_connect avg took`는 호출 하나의 시간이 아닙니다. 고정 소스는 반복 횟수의 처음 10%를 timer 재시작으로 제외하고, `wolfSSL_new`·키 공유 준비·TCP connect·TLS connect·shutdown·객체/소켓 정리를 포함한 반복 전체를 나눕니다. 컨텍스트 셋업은 밖에 있습니다. `-b 2`이면 버리는 연결 수는 0이므로 캐시 준비와 재사용 연결이 평균에 함께 들어갑니다. 이 예제가 논문 처리시간 실험의 정확한 측정기였는지는 확인되지 않았습니다. [고정 원본 코드](https://github.com/RWTH-SPICe/BiTHaC/blob/68ad825a37ef72cc1db4a67eb6d13275cc61f8aa/examples/client/client.c#L490)

| 비교할 관측 | TURTLE의 대응과 차이 |
|---|---|
| 논문의 연결 전체 네트워크 바이트 | pcap은 SYN·ACK·FIN을 보존합니다. 현재 TCP 요약 합계는 TLS 데이터 패킷만 대상이므로 논문의 전체 트래픽 감소율과 같은 분모가 아닙니다. |
| 공개 예제 반복 평균 | TURTLE은 연결 위치별로 보고하고 첫 측정 연결을 자동 제외하지 않습니다. 연결 객체 준비 순서·shutdown·키 생성 배치도 달라 기존 JSONL만으로 예제 시간을 정확히 복원할 수 없습니다. |
| E2E 핸드셰이크 | TURTLE은 클라이언트 TCP 시작/연결 준비 시작→ClientFinished 제출, 서버 첫 수신→ClientFinished 처리와 API 완료를 각각 제공합니다. 논문의 불명확한 경계를 임의로 이 중 하나와 동일시하지 않습니다. |
| 준비·캐시 비용 | 첫 빈 캐시 연결과 이후 연결, 모듈·컨텍스트 전체 구간을 남깁니다. 논문의 캐시 준비 제외 수치를 그대로 재현한 표가 아닙니다. |
| 메모리 최대값 | TURTLE의 라이브러리 할당 훅은 정적 캐시·스택·전체 프로세스 RSS를 포함하지 않습니다. Bytehound 수치와 관측 범위를 맞추기 전 직접 비교하지 않습니다. |

공개 TLS 1.3 경로는 작은 사전 검증 캐시를 지원하지 않으므로 논문 처리시간 최적화 전체가 재현됐다고 주장하지 않습니다. 현재 확인한 기법은 실제 양방향 인증서 캐싱과 바이트 감소입니다. 정확한 논문 timing 경계·측정기 연결과 원 환경의 정량 재현은 미완료로 남깁니다. 출처·파일 해시와 이 대응은 `artifacts/bithac-measurement-mapping.json`에도 보존합니다.

새로 채택한 후보에서 공개 코드를 확보하지 못하면 메시지·상태·암호 연산·준비 조건을 추출한 재현 명세에 따라 직접 구현합니다. 핵심 명세가 부족한 부분은 가정과 미완료 이유를 남깁니다.
