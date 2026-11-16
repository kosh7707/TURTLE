# 네트워크와 커널 관측

`network.py`는 별도의 소유 네트워크 네임스페이스에서 조정자를 시작하고, 그 안에서 클라이언트·서버·라우터와 선택적 MockCA의 네임스페이스를 만듭니다. 호스트의 기존 인터페이스나 qdisc를 바꾸지 않습니다. 준비 전후 호스트 링크·라우트·qdisc를 비교하고 소유 프로세스·FD·관측 링크의 정리 결과를 보존합니다. 임시 네임스페이스 내부의 ip_forward만 설정합니다.

```sh
python3 scripts/build-kernel-observer.py --output build-message/kernel-observer.bpf.o
sudo python3 scripts/network.py --network examples/message/network.json \
  --output results/network
```

권한이 필요한 실제 네트워크 작업은 이 명령에만 적용합니다. 스크립트는 비밀번호를 읽거나 저장하지 않습니다. 커널 관측을 끄면 지원되는 환경에서 사용자 네임스페이스로 실행할 수도 있습니다. 필요한 ip, tc, ethtool, unshare, nsenter와 선택적 Clang BPF·libbpf·커널 BTF를 확인합니다. 없는 기능을 성공한 것으로 대체하지 않습니다.

계약은 `turtle-message-network-plan/1`입니다. tls_c2s와 tls_s2c, MockCA 사용 시 ca_c2s와 ca_s2c에 delay_ms, loss_percent, rate_bps, limit_packets를 지정합니다. rate_bps는 8의 배수입니다. initial_cwnd는 client와 server의 시작 세그먼트 수입니다. netem은 라우터의 수신자 방향 egress에 배치하며 TLS 데이터 포트 44330과 조회 포트 44332만 분류합니다. 제어 포트 44331은 이 분류에서 제외합니다. `tc -j -s`, `ip -j route get`, ethtool로 실제 값과 offload·MTU를 확인합니다. netem 난수 seed의 실제 적용 검증은 미지원이며 null 이외의 값은 받지 않습니다.

패킷 원본은 nanosecond pcap, 위치·방향·TCP 정보는 JSONL로 보존합니다. 관측 위치는 라우터 veth의 AF_PACKET입니다. 각 행은 가능한 경우 SO_TIMESTAMPNS의 커널 skb 시각을 보존하고, 그렇지 않으면 userspace 수신 후 시각임을 표시합니다. CLOCK_REALTIME과 단조 시계의 조회 쌍·범위를 남기지만 NIC 하드웨어 시각이나 정확한 물리선 전송 시각으로 부르지 않습니다. 캡처 소켓의 누락 통계도 결과에 남깁니다. 관측기는 파일 출력과 파싱을 하는 별도 프로세스이며 수집 부담이 없는 실험이 아닙니다.

`packet-report.json`은 SYN으로 방향별 TCP 바이트 기준을 정하고, 실제 원본 바이트를 프레임워크 송신 스트림과 대조합니다. 연결 순서는 해당 소유 네트워크에서 이 실행이 만든 TLS 연결 순서입니다. 패킷→스트림 범위→레코드→논리 메시지 관계를 기록합니다. 라우터 입구와 출구의 두 관측을 재전송 두 번으로 세지 않습니다. 같은 위치의 중첩 바이트는 중복 관측이라는 진단이며 커널 재전송 사건과 다릅니다.

커널 수집기는 소유 네임스페이스의 흐름으로 제한하고 `targeted_drop`, `qdisc_drop`, `tcp_retransmit_skb`를 구별합니다. 지정 손실은 방향별 TLS 스트림 바이트를 포함하는 최초 패킷을 tc에서 한 번 제거합니다. netem 설정의 손실 확률은 실제 제거 횟수가 아니므로 qdisc 제거 사건과 따로 보존합니다. ring buffer 누락, 흐름 추적 누락, 수집 종료·정리 실패를 확인해야 관측을 available로 읽을 수 있습니다. 원본 BPF 오브젝트·소스 해시·커널 BTF 해시를 함께 저장합니다.

MockCA 네트워크 옵션 `--object FILE`은 클라이언트 조회를 별도 조회 경로와 서비스에 연결합니다. 서버의 조회도 일반 실행 명세로 독립 설정할 수 있지만 이 고정 네트워크 토폴로지의 조회 경로는 클라이언트용입니다. TLS 실행 루프나 메시지 ID를 별도로 만들지 않습니다.
