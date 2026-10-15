# 보고서의 측정 구간과 비교 후보

`turtle-report`는 원자료인 `client.jsonl`과 `server.jsonl`만 있어도 기본 보고서를 만듭니다.
기본 측정 구간은 클라이언트와 서버를 따로 다룹니다. 클라이언트에서는 첫 핸드셰이크
호출부터 성공한 퐁 수신 호출이 끝날 때까지를 재고, 서버에서는 첫 성공한 수신부터 성공한
퐁 송신 호출이 끝날 때까지를 잽니다. 해독 파일이 없거나 완전하지 않아도 이 기본 결과는
바뀌지 않습니다.

## 클라이언트의 대체 측정 구간

같은 표본 폴더에 `client.decoded.json`이 있으면 보고 도구는 다음 대체 구간을 계산할 수
있습니다.

1. 시작은 ClientHello를 담은 TLS 레코드의 바이트 구간과 겹치는 첫 번째 성공한
   `IO_SEND_RETURN` 사건입니다.
2. 끝은 클라이언트의 Finished를 담은 TLS 레코드의 마지막 바이트까지 보낸 성공한
   `IO_SEND_RETURN` 사건입니다.

보고서는 이 두 사건 사이의 경과 시간과 스레드 CPU 시간을 기록합니다. 성능 카운터가
표본 전체에서 완전하고 두 사건의 값도 있으면 사이클 수도 기록합니다. 시작과 끝에 사용한
원자료 사건의 `sequence` 값도 함께 기록하므로, 어떤 사건을 경계로 골랐는지 다시 확인할 수
있습니다.

이 구간은 클라이언트가 자기 Finished를 네트워크로 넘긴 시점에서 끝납니다. 따라서 그 뒤에
서버가 보내는 NewSessionTicket은 포함하지 않습니다. 다만 서버가 NewSessionTicket을 더
일찍 보내고 클라이언트가 자기 Finished를 보내기 전에 처리했다면 그 대기나 처리는 구간에
들어갈 수 있습니다. 이 수치만으로 NewSessionTicket 처리 비용을 따로 떼어 냈다고 해석하면
안 됩니다.

해독 결과가 알려 주는 것은 평문 메시지가 들어 있는 TLS 레코드 전체의 바이트 구간입니다.
하나의 레코드나 하나의 입출력 반환에 여러 평문 메시지가 함께 들어갈 수 있습니다. 보고서는
ClientHello와 Finished 경계의 묶임 여부를 각각 표시합니다. 이 대체 구간은 레코드 전체를
기준으로 잡은 구간이며, Finished 같은 평문 메시지 하나의 CPU 시간을 따로 잰 값이 아닙니다.

보고 도구는 해독 파일의 형식 번호, 표본 번호, 역할, 연결 번호가 원자료와 모두 맞는지
확인합니다. 연결이 빠졌거나 중복되었거나 해독이 끝나지 않은 파일은 대체 구간 계산에 쓰지
않습니다. 각 역할의 표본 결과에는 해독 파일을 사용했는지, 파일이 없었는지, 오류 때문에
무시했는지와 그 이유를 따로 남깁니다. 이때도 원자료만으로 만든 기본 보고서는 그대로
남습니다.

## 자동 비교 후보

자동 비교는 같은 역할을 측정한 두 그룹 가운데 실행 조건이 같은 경우만 후보로 냅니다.
클라이언트를 측정할 때는 클라이언트 어댑터 이름과 그 라이브러리 이름, 버전, 빌드 옵션만
달라도 됩니다. 서버 어댑터는 같아야 합니다. 서버를 측정할 때는 반대로 서버 쪽 식별 정보만
달라도 되고 클라이언트 어댑터는 같아야 합니다.

프로필, 실행 제어값, 컨텍스트를 불러왔는지 여부, CPU 고정 결과, 측정 모드, 관측 수준,
환경은 같아야 합니다. 이 규칙은 측정하는 쪽의 구현을 바꾸면서 상대 엔드포인트를 고정한
후보를 찾기 위한 것입니다.

상대 엔드포인트가 고정되었는지는 같은 표본 폴더의 반대 역할 원자료 머리글로 확인합니다.
두 머리글의 표본 번호, 묶음 번호, 프로필이 맞아야 합니다. 비교 조건에는 양쪽에 실제로
고정된 CPU 번호와 상대 어댑터의 라이브러리 이름, 버전, 빌드 옵션, 유효 여부, 계측 지원
정보가 들어갑니다. 반대 역할 파일이 없거나 머리글을 확인하지 못한 단일 역할 결과도
요약에는 남지만 자동 비교 후보에서는 제외합니다. `director.txt`가 표본을 무효라고
표시하면 그 폴더의 역할 결과도 유효한 그룹에 넣지 않습니다.

두 그룹이 포함한 묶음 번호의 집합도 완전히 같아야 합니다. 서로 다른 묶음에서 나온 두
그룹을 자동으로 비교하지 않습니다.

양쪽 엔드포인트가 조회한 실제 소켓 설정도 비교 조건에 포함합니다. 준비 연결과 측정 연결의
실제 설정을 모두 순서대로 조건 identity에 넣습니다. 요청 버퍼 크기가 같더라도 커널이 적용한
값이 다르면 그룹을 나눕니다. 연결의 `socket`이 없는 예전 자료는
미관측으로 유지하며 새 자료의 조회값으로 대신 채우지 않습니다.
자기 역할이나 상대 역할의 실제 소켓 설정이 빠진 자료는 요약만 만들고 자동 비교에서는
제외합니다.

컨텍스트 입력은 양쪽 역할의 크기와 `loaded_context_hash`로 구분합니다. 같은 크기의
서로 다른 저장본을 한 초기 상태로 취급하지 않습니다. 비어 있지 않은 입력인데 지문이
없는 예전 자료는 원자료 요약만 만들고 자동 비교 후보에서는 제외합니다.

한 표본에서 여러 연결을 측정하면 `connection` 번호별로 그룹을 나눕니다. 예를 들어 준비
연결 1개와 측정 연결 2개를 표본 10개에서 실행하면, 각 역할의 연결 1과 연결 2 분포에
각각 10개 값이 들어갑니다. 같은 프로세스에서 얻은 두 연결을 독립 표본 20개로 합치지
않습니다. 전체 연결 수와 준비 연결 수도 비교 조건에 포함합니다.

후보의 차이와 95퍼센트 구간은 두 그룹을 독립적으로 다시 뽑는 부트스트랩으로 계산합니다.
이 결과는 탐색적인 비교 후보일 뿐입니다. 두 구현이 같은 동작을 한다거나 결과가 서로
같다는 것을 판정하지 않습니다.

### 순수 TLS의 격리 네트워크 조건

조회 원자료가 없는 일반 TLS 실행도 network handoff가 있으면 요청 정책과 실제 적용 정책을
모두 안정 그룹 키에 넣습니다. 요청 identity는 역할 원자료의 `network_handoff.net_profile`,
실제 identity는 provenance에서 변동값을 제거한 topology·활성 경로·qdisc readback·MTU·offload
조건입니다. 따라서 0ms와 20ms 또는 client와 server 역할은 서로 다른 그룹이며, CA 경로가
없는 세 namespace topology는 조회용 네 namespace topology와 섞이지 않습니다.

host unchanged, phase observation 완전성, helper/observer 회수 같은 integrity **결과**는 안정
그룹 키에 넣지 않습니다. 같은 요청·실제 정책에서 integrity 결과가 달라도 조건 그룹을 새로
만들지 않고, 원래 run-level provenance·attempt metadata와 표본의 `network_integrity`, 그룹의
최상위 `automatic_comparison_eligible`에서 부적격을 표시합니다. 부적격 표본의 측정값은 그룹
metric에 넣지 않습니다. success/timeout, drop, retrans도 같은 이유로 조건 키가 아닙니다.

준비 연결과 측정 연결의 실제 소켓 설정은 모두 조건을 구성하지만, 경과 시간·스레드 CPU를
비롯한 metric에는 `warmup=false`인 측정 연결만 들어갑니다. 준비 연결을 표본 수나 metric 수에
더하지 않습니다.

## 인증서 조회 시나리오 보고

조회 원자료가 있으면 `turtle-report`는 기존 `summary.json`과 별도로 `lookup-summary.json`을 만듭니다. 보고서 제목과 `scenario_disclosure`는 이 실행이 **합성 조회 + stock 인증서 기반 TLS**이며 인증서 경량화 결과가 아님을 명시합니다.

### 분모와 상태

`attempts.jsonl`의 parent 최종 행이 상태의 기준입니다. 자식 파일의 `valid=true`가 parent의 timeout/error를 덮지 않습니다. 원장에는 다음 항등식이 유지되어야 합니다.

```text
requested = started + not_attempted
started = success + timeout + error + incomplete
```

`attempt_table`은 attempt 상태와 그 attempt에 속한 연결 행 참조를 담습니다. `connection_table`은 warmup 여부와 연결 상태를 담습니다. 여러 연결의 시간을 더해 독립 attempt 시간으로 만들지 않습니다. timeout의 누락값을 성공 분포에 timeout 길이나 0으로 넣지 않습니다. 과거 원자료에 원장이 없으면 TLS header와 `director.txt` fallback을 명시적으로 표시하며, 새 원장이 있을 때는 fallback으로 상태를 바꾸지 않습니다.

### 연결 행의 시간과 자원

`joined_rows`는 lookup·CA·TLS와 network observation을 `(attempt, connection, request_id)` 및 observation ID로 연결합니다.

- `remote_lookup_duration_ns`: miss의 `REQUEST_BEGIN`→`RESPONSE_COMPLETE`입니다. hit이면 not-applicable `null`입니다.
- `usable_duration_ns`: 조회 시작→`USABLE_OBJECT`입니다. 응답 수신 뒤 바이트 대조와 cache insert를 포함합니다.
- `tls_elapsed_ns`: 기존 클라이언트 TLS 경계입니다. 조회 시간이 섞이지 않습니다.
- `scenario_elapsed_ns`: 조회 시작부터 TLS 완료까지의 시나리오 경계입니다.
- `ca_process_ns`, `ca_cpu_ns`, `ca_io_ns`, `ca_wait_ns`: 모의 CA 엔드포인트의 독립 경계입니다.
- `tcp_counter_deltas`: lookup, CA, TLS client, TLS server 소켓의 시작/끝 차이입니다.

CA process, I/O, wait는 서로 겹치거나 포함 관계가 있을 수 있는 관측 경계입니다. `remote_lookup_duration_ns`를 RTT라고 부르거나 CA 시간과 더해 총시간을 만들지 않습니다. 보고서도 `ca_plus_rtt=never_summed` 규칙을 남깁니다.

### 손실 근거와 조건 그룹

netem 요청 loss는 조건이고, qdisc actual drop은 skb 집계 결과이며, `TCP_INFO.total_retrans` 차이는 소켓의 TCP 재전송 결과입니다. 세 값은 단위와 관측 위치가 다릅니다. AF_PACKET packet도 물리 wire packet이 아닙니다. TSO/GSO/GRO 요청·실제 readback을 함께 읽어야 하며, qdisc 집계를 특정 connection에 나눠 주거나 연결 수만큼 더하지 않습니다.

조건 그룹에는 합성 시나리오, cache mode와 초기 상태, 객체 ID·크기, TLS 프로필, 연결 정책, 실제 CPU·소켓 준비값, topology, 방향별 qdisc 정책, MTU, offload 요청·실제값 같은 안정 조건만 넣습니다. namespace PID/FD/path, 동적 port, qdisc handle, timestamp 같은 provenance와 success/timeout, drop, retrans 같은 **결과**는 그룹 키에서 뺍니다. 결과가 다르다는 이유로 같은 조건을 서로 다른 그룹으로 나누지 않습니다. 반대로 필수 조건 identity가 없거나 실제 offload·MTU·소켓 준비값이 다르면 자동 비교에서 제외하거나 그룹을 나눕니다.

고정 netem 검증 manifest의 일곱 실행은 각 run의 원장·네트워크 provenance·host unchanged·소유 자원 cleanup integrity를 통과했습니다. 최신 보고 도구는 성공한 network attempt마다 setup/scenario/cleanup begin/end의 정확히 여섯 observation 참조를 확인하고, host unchanged 및 owned cleanup과 함께 자동 비교 적격성에 반영합니다. 참조·provenance·원장이 누락되거나 잘못되면 fail closed입니다.

loopback 자료는 네트워크 integrity가 not-applicable이므로 측정값을 설명용 분포에 남길 수 있습니다. 그러나 격리 topology·실제 적용 network identity가 없으므로 자동 network 비교 적격성은 얻지 않습니다. **설명용 metric 보존과 비교 적격성은 별도 판단입니다.**

`results/mock-ca-goal/netem-verify-final/report-final/lookup-summary.json`은 보존한 일곱 실행을 합산합니다. requested=started=100, success=97, timeout=3이며 attempt table, connection table, joined rows가 각각 100개입니다. 일곱 조건은 각각 자기 분모와 condition group을 유지합니다. timeout 세 건은 비교 분포에 들어가지 않습니다.

194개 유효 TLS 역할 파일은 모두 해독됐습니다. timeout에서 없거나 유효하지 않은 역할 파일 6개는 그대로 결측으로 남겨 성공으로 승격하지 않았습니다. `latency-diagnostics.json`의 중앙값은 경로 동작을 보는 `diagnostic_only` 값이며 어떤 gate도 latency 임계값으로 판정하지 않습니다. 논문 성능 주장에도 사용하지 않습니다.
