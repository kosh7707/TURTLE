# 원본 패킷과 TLS 바이트 대응

`scripts/netem-study.py`의 기존 소유 이름공간 실행에서 네트워크 프로필의 `trace=true`를 선택하면 `packets.jsonl`과 `packets.pcap`을 보존합니다. 순수 TLS는 클라이언트·라우터·서버 이름공간과 veth 두 링크를 사용합니다. MTU·TSO/GSO/GRO는 요청 후 재조회하며 기존 qdisc·손실 조건과 정리 기록도 유지합니다.

현재 로컬 실험은 TLS 엔드포인트 프로세스 두 개를 이 경로에 배치합니다. 서버 수신 대기 포트 하나와 클라이언트 임시 포트로 연결하며, 방향마다 TCP 연결이나 수신 대기 포트를 추가하지 않습니다. 클라이언트→서버 조건은 라우터 `rstls`, 서버→클라이언트 조건은 `rctls` 출구의 netem에 적용합니다. 수신자 직전 경로에 두는 것은 송신자 TCP 큐와 지연 주입의 상호작용을 줄이기 위한 배치입니다. [netem의 TCP 배치 설명](https://man7.org/linux/man-pages/man8/tc-netem.8.html)

`examples/networks/tls-no-loss.json`, `tls-c2s-delay20.json`, `tls-s2c-delay20.json`, `tls-both-delay10.json`은 무지연, 한 방향 20ms, 양방향 각각 10ms의 별도 조건입니다. 모두 무손실·MTU 1500·offload 끔이며 속도·초기 cwnd는 기본값입니다. netem 조건은 시행 시작 전에 고정하고 실제 적용값을 재조회합니다. 전체 시행 중 방향을 바꾸며 측정하지 않습니다.

pcap은 나노초 형식의 Ethernet 프레임 원본입니다. IPv4/TCP 헤더·옵션·payload를 잘라내지 않습니다. JSON의 `packet_index`, `pcap_offset`으로 원본과 연결하고 TCP/IP 헤더 길이·옵션·payload 위치를 따로 남깁니다. 관측 단위는 AF_PACKET에서 받은 소프트웨어 프레임이며 물리 NIC 프레임이나 하드웨어 시각이 아닙니다.

패킷 시각은 `recvfrom` 뒤 사용자 공간에서 읽습니다. pcap에는 CLOCK_REALTIME, JSON에는 CLOCK_MONOTONIC과 실시간 시계를 읽기 전후의 단조 시계 구간을 보존합니다. 이 구간 폭보다 정밀한 두 시계 대응을 주장하지 않습니다. 소켓의 SO_TIMESTAMPNS 수신 사건과 아래 선택적 커널 송신 사건은 관측 위치가 다릅니다.

## 커널 송신 요청 관측

TLS 실행의 `--mode trace --tx-timestamps` 또는 프로필의 `measurement.tx_timestamps=true`로 `SO_TIMESTAMPING`을 켭니다. `TX_SCHED`, `TX_SOFTWARE`, `TX_ACK`, `SOFTWARE`, `OPT_ID`, `OPT_TSONLY`, `OPT_ID_TCP`를 요청합니다. 프레임워크 비차단 I/O와 관측자가 필요하며 기본 시간 실행에서는 끕니다. [Linux timestamping 계약](https://docs.kernel.org/networking/timestamping.html)을 따릅니다.

`KERNEL_TX_SCHED`는 송신 스케줄러 진입 전, `KERNEL_TX_SND`는 커널 소프트웨어 송신, `KERNEL_TX_ACK`는 누적 ACK 관측입니다. `MSG_ERRQUEUE`에서 받은 CLOCK_REALTIME 원시 시각과 그 사건을 수집한 CLOCK_MONOTONIC 스냅샷을 따로 저장합니다. 소프트웨어 송신을 물리 NIC 출발로 부르지 않습니다. 가상 장치 계층이 여러 개이면 하나의 요청에서 스케줄러 사건이 여러 번 올 수 있습니다.

`timestamp_id`는 TCP 송신 요청의 마지막 바이트 번호이며 `stream_end=id+1`입니다. 전체 TCP 세그먼트·TLS 레코드의 정확한 시각 범위가 아니므로 `timestamp_coverage_exact=false`를 유지합니다. 송신 요청 하나에 여러 세그먼트가 있을 수 있고 재시도·부분 송신과도 구별합니다. ID 순환을 해석하지 않으므로 추적 버퍼가 2^32바이트 미만인 실행만 허용합니다. `TX_ACK`는 SACK이 아닌 누적 확인이며 해당 prefix 끝까지 받은 상태를 뜻합니다.

양쪽 정상 시나리오가 끝난 뒤 정리 구간에서 마지막 ACK를 최대 100ms 더 수집합니다. 이 대기를 완료시간에 넣지 않습니다. 시간 안에 없는 관측을 만들거나 TLS 성공을 관측 실패로 바꾸지 않습니다. 설정·수집 errno, 세 단계의 누락, 마지막 제출 바이트 ACK 여부를 `prototype.kernel_transmit`에 남깁니다. `tcp-correlate.py`는 각 메시지의 레코드 바이트를 포함하는 커널 요청 사건과 최초 누적 ACK도 연결합니다.

## 속도와 초기 혼잡 윈도

네트워크 프로필 schema 2의 각 방향 `rate_bps`는 bit/s 또는 제한 없음 null이며, `initial_cwnd.client/server`는 TCP 초기 혼잡 윈도의 세그먼트 수 또는 기본값 null입니다. schema 1의 기존 모양·뜻은 바꾸지 않습니다. `examples/networks/tls-1mbit-cwnd4.json`은 MTU 1500, offload 끔, 각 방향 5ms·1Mbit/s, 양쪽 초기 cwnd 4입니다.

속도는 해당 라우터 방향의 netem에, 초기 cwnd는 엔드포인트의 상대 TLS 주소 경로에 적용합니다. `tc -j`의 byte/s를 bit/s로 환산해 확인하고 `ip -j route get`의 initcwnd와 연결 시작 `TCP_INFO.snd_cwnd`도 대조합니다. 요청값만으로 적용됐다고 판단하지 않습니다. 실제 적용값을 네트워크 비교 조건에 포함합니다. 경로 설정은 수신 윈도나 서버 응용 버퍼 크기와 다릅니다.

## 재구성

```sh
build/turtle-interpret RESULTS/sample-000001/client.jsonl \
  RESULTS/sample-000001/client.decoded.json
python3 scripts/tcp-correlate.py RESULTS/packets.jsonl \
  RESULTS/sample-000001/client.jsonl RESULTS/sample-000001/client.tcp.json
```

서버에도 같은 절차를 적용합니다. 분석기는 먼저 연결의 전체 송신 TLS 스트림과 TCP 재구성 바이트가 같은 유일한 흐름을 찾습니다. 일치하지 않거나 캡처 완료·drop=0 근거가 없으면 누락 상태를 남깁니다. 원본 pcap이 없는 과거 자료는 미지원입니다. 해독에 실패한 TLS 자료로 메시지 대응을 만들지 않습니다.

한 방향은 송신 엔드포인트 쪽 라우터 인터페이스의 ingress만 셉니다. 같은 패킷이 다른 라우터 인터페이스에서 다시 보였다고 재전송으로 세지 않습니다. SYN 다음을 TLS 스트림 0으로 두고 TCP 32비트 순번 순환, 부분 중첩과 누적 ACK를 처리합니다. 같은 위치에서 앞서 관측한 바이트와 겹친 양을 `observed_retransmitted_payload_bytes`로 남깁니다. 이는 커널 `tcp_retransmit_skb` 사건과 구별합니다.

각 TLS 메시지는 해독한 레코드 외곽 범위, 성공한 소켓 제출 사건, 관련 최초·반복 전송 패킷과 그 범위를 확인한 첫 누적 ACK로 연결됩니다. ACK는 같은 인터페이스의 반대 방향 egress 관측이며 송신 소켓의 ACK 완료 시각이 아닙니다. SACK의 독립 해석은 미지원이고 TCP 옵션 원문은 보존합니다. 레코드를 공유하는 메시지에 헤더·암호화·전송 비용을 나누어 배정하지 않습니다.

합계의 IP/TCP 헤더 바이트와 payload는 해당 방향의 TLS 데이터 패킷 대상입니다. 재전송은 별도 합산하고 순수 ACK·SYN·FIN도 원본 pcap에는 남습니다. 모든 프로토콜의 범용 pcap 분석기가 아니며 현재 제어 환경의 비단편 IPv4/TCP·Ethernet을 대상으로 합니다.

## 지정 바이트 손실과 커널 재전송

네트워크 프로필 schema 3은 `kernel_events`와 `targeted_drop.tls_c2s/tls_s2c`를 추가합니다. 방향별 값은 TLS 스트림의 0부터 시작하는 바이트 위치이며 null이면 지정 손실을 사용하지 않습니다. `tls-target-client-first.json`, `tls-target-server-first.json`, `tls-kernel-no-loss.json`이 예시입니다. 이 프로필은 패킷 추적과 TSO/GSO/GRO 끔을 요구합니다. 이전 schema 1·2의 뜻과 기본 실행은 유지합니다.

```sh
# 의존성 준비 때만 고정 libbpf 1.6.3 헤더를 받습니다.
python3 scripts/build-kernel-observer.py --fetch-headers
sudo python3 scripts/netem-study.py run --build build \
  --profile examples/profiles/server-auth.json \
  --net-profile examples/networks/tls-target-server-first.json \
  --client openssl --server wolfssl --samples 2 --output results/target-loss

# 세 라이브러리의 정상 복구·원자료·보고서를 함께 검증합니다.
sudo python3 scripts/kernel-loss-study.py run --build build --pki pki/default \
  --output results/kernel-loss
python3 scripts/kernel-loss-study.py analyze --build build --output results/kernel-loss
```

Clang BPF target, 실행 커널 BTF, `libbpf.so.1`이 필요합니다. 이번 검증은 Clang 21.1.8과 libbpf 1.6.3을 사용했습니다. libbpf는 BPF 오브젝트의 CO-RE 재배치, tc·tracepoint 연결, map·ring buffer 수집에만 사용합니다. 빌드 manifest에 고정 libbpf 1.6.3 헤더·소스·오브젝트 해시와 컴파일러 명령을 남기며 실행 중 다운로드하지 않습니다. 실행 때 로드한 libbpf 판도 커널 자료에 남깁니다. 실행기는 요청한 경우에만 initial user namespace의 root를 요구하고, 호스트와 분리한 새 network namespace를 만듭니다. 이 경로의 엔드포인트도 root로 실행되며 권한 종류를 비교 조건에 기록합니다. 일반 user namespace 실행과 섞어 성능 비교하지 않습니다. 호스트의 qdisc·인터페이스·tracefs 설정은 바꾸지 않습니다.

tc clsact egress 프로그램이 SYN/SYN-ACK 다음 순번을 기준으로 연결·방향별 위치를 계산합니다. 지정 위치를 포함하는 첫 payload 패킷에 한 번만 `TC_ACT_SHOT`을 반환하고 이후 전송은 통과시킵니다. 요청한 한 바이트만 잘라내는 방식이 아니라 그 바이트를 포함하는 **실제 소프트웨어 패킷의 전체 TCP payload 범위**를 제거합니다. 조건은 연결 중 변경하지 않습니다. netem root qdisc와 분리돼 있어 시행 준비 때 netem을 재설정해도 제어가 유지됩니다.

`kernel-events.json`에는 지정 제거, `tcp_retransmit_skb`, `SKB_DROP_REASON_QDISC_DROP`를 구별해 남깁니다. 재전송은 시퀀스·종료 순번·오류 코드가 있는 커널 사건이며 전달 성공 자체가 아닙니다. qdisc 제거에는 순수 ACK·SYN·FIN도 포함될 수 있어 사건 수가 재전송 수와 같을 필요는 없습니다. CO-RE가 실행 커널 BTF에서 소켓·skb 필드 위치를 결정하며, 실행 소유 네임스페이스 inode와 TLS 흐름으로 제한합니다. [커널 재전송 사건 정의](https://github.com/torvalds/linux/blob/v6.18/include/trace/events/tcp.h)

커널 사건 시각은 `bpf_ktime_get_ns`의 단조 시각입니다. 사용자 공간 수집 시각·AF_PACKET 관측·실시간 시계 송신 알림과 구별합니다. 4MiB ring buffer와 65,536개 사용자 공간 사건 버퍼를 미리 확보하고 측정 중에는 고정 구조만 복사합니다. 해석·JSON 출력은 종료 뒤 수행합니다. 흐름 map은 8,192개이며 초과·읽기 실패·ring/사용자 버퍼 누락은 0으로 대체하지 않습니다. 요청한 target에 도달하지 않은 흐름도 미완료로 남깁니다.

종료 때 tc·tracepoint 링크·map·FD를 해제하고 소유 네임스페이스를 정리합니다. 수집 누락·지정 손실 미실현·보조 프로세스 정리 누락은 TLS 성공과 별도로 기록되며 일반 보고서의 자동 비교에서 제외됩니다. TCP 분석 schema 2는 실제 커널 사건 인덱스를 TLS 레코드·메시지에 연결하고, 커널 미수집의 null과 관측한 재전송 0을 구별합니다.

## 실제 확인과 유보 범위

- 무손실 0/20ms의 실제 TLS 네 연결을 통합 시험에서 검증하며 Finished의 레코드·소켓 제출·패킷·ACK 대응을 확인합니다.
- [송신 시각 행렬](../../artifacts/tx-timestamp-matrix-1/verification.json)은 세 라이브러리 × 네 시나리오 × 새 TCP 두 연결입니다. 48개 역할/연결에서 세 종류 커널 사건과 최종 바이트의 누적 ACK를 확인했습니다.
- [속도·초기 윈도 검증](../../artifacts/network-tx-pilot-2/verification.json)은 양방향 1Mbit/s·5ms·initcwnd=4, 64KiB 응용 교환에서 실제 TCP_INFO와 원본 패킷·Finished의 커널 ACK를 대조합니다.
- [커널 손실 행렬](../../artifacts/kernel-loss-matrix-final/verification.json)은 세 라이브러리 × 다섯 조건 × 두 새 프로세스 쌍 × 컨텍스트당 두 연결입니다. 60개 실제 TLS 연결·120개 역할/연결에서 양방향 32KiB, 스트림·패킷 일치와 정상 복구를 확인했습니다. 지정 제거 48건은 각각 후속 커널 재전송과 대응하며, 랜덤 5% 조건의 qdisc 제거는 51건입니다. seed는 고정되지 않았습니다.

네이티브 Linux의 패킷·BPF 관측 부담 평가와 ARM의 BTF·도구 호환성 재확인은 사용자 요청으로 유보합니다. 최신 회귀 검증과 자료의 해석 한계는 [검증 문서](../project/validation.md)를 따릅니다.
