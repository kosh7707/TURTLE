# 모의 CA와 격리 netem 실행

## 시나리오의 정확한 범위

`synthetic-lookup-plus-standard-tls`는 **합성 인증서 객체 조회 뒤 표준 인증서 기반 TLS를 실행하는 시나리오**입니다. 표준 TLS 1.3 핸드셰이크 자체에 실시간 CA 통신을 추가한 프로토콜이 아닙니다.

1. 지휘 프로세스가 `lookup.object_file`의 공개 PEM 바이트를 실행 시작 때 한 번 읽고, 크기와 FNV-1a 객체 ID를 계산합니다.
2. 이 불변 기준 객체는 전체 실행 동안 미리 보유합니다. 모의 CA도 같은 원본을 자기 응답 저장공간에 미리 복사합니다.
3. 각 연결 시작 때 클라이언트 조회 캐시를 `empty` 또는 같은 고정 snapshot으로 직접 복원합니다. 앞 연결의 캐시 변경을 다음 연결에 누적하지 않습니다.
4. miss이면 준비된 별도 TCP 연결로 44바이트 요청을 보내고 원본 PEM 응답을 받습니다. hit이면 응용 조회 요청은 0건이며, 준비 TCP 연결이 존재한다는 사실과 혼동하지 않습니다.
5. 클라이언트는 응답의 ID·길이·원본 바이트를 기준 객체와 대조하고 캐시에 삽입합니다. `RESPONSE_COMPLETE`는 수신 완료일 뿐이며, 비교와 삽입을 마친 `USABLE_OBJECT` 뒤에만 TLS를 시작합니다.
6. stock TLS 어댑터는 프로필의 정상 인증서·키 파일을 그대로 사용해 전체 핸드셰이크와 암호화된 핑퐁을 수행합니다.

조회 결과는 네트워크 응답 검증과 캐시 삽입에 실제로 소비됩니다. 그러나 어댑터의 인증서 입력으로 전달되지는 않습니다. 따라서 stock TLS의 Certificate 메시지는 그대로 존재하며, 인증서 생략·압축·검증 재사용 또는 BiTHaC 효과를 주장하지 않습니다. 보고서도 이 제한을 명시합니다.

## 객체·wire·캐시 계약

- 객체는 줄바꿈을 포함한 원본 PEM 1~65,536바이트입니다. 기본 `object_file`은 최종 `tls.server_certificate`입니다.
- 객체 ID는 `fnv1a64:`와 소문자 16진수 16자리입니다. 이는 식별값이지 보안 해시가 아닙니다. 동일성은 크기와 원본 바이트로 확인합니다.
- wire 머리는 정확히 44바이트입니다. `TCA1`, version, request/response kind, attempt, connection, request ID, object ID, payload 길이, 상태를 network byte order로 저장합니다. 연결별 request ID는 1입니다.
- request는 payload가 없습니다. 성공 response는 원본 PEM을 그대로 담고, 정의된 오류 response만 payload 없이 status 1을 씁니다.
- `Cache`는 생성 때 65,536바이트를 선확보합니다. `restore`와 `insert`는 이 공간 안에서 복사하거나 지웁니다. `fixed-snapshot`은 준비 단계에서 JSON의 hex, 길이, ID와 기준 원본 일치를 확인해야 합니다.
- 기준 객체, 캐시의 논리 바이트·용량, framework 고정 예약 공간은 서로 다른 값입니다. 예약 용량을 heap 사용량에 다시 더하지 않습니다.

snapshot 형식은 다음 필드만 가집니다.

```json
{
  "type": "turtle-lookup-cache",
  "schema": 1,
  "object_id": "fnv1a64:0123456789abcdef",
  "object_size": 123,
  "object_hex": "...원본 PEM의 소문자 16진수..."
}
```

직접 작성하지 말고 원본에서 생성합니다. 출력 파일이 이미 있으면 덮어쓰지 않습니다.

```sh
python3 scripts/netem-study.py snapshot \
  --object pki/netem/server-chain.pem \
  --output configs/warm-cache.json
```

## 프로필 설정

조회 설정은 별도 CLI 옵션이 아니라 실행 프로필에 둡니다. `samples`는 항상 요청 attempt 수입니다. 한 attempt 안의 `connections`는 별도 attempt가 아니며, `warmups`는 성공 시간 분포에서 제외합니다.

```json
{
  "name": "lookup-example",
  "pki": "../pki/netem",
  "tls": {
    "version": "TLS1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "group": "secp256r1",
    "signature": "ecdsa_secp256r1_sha256",
    "server_name": "localhost",
    "mutual_auth": false,
    "compatibility_ccs": true,
    "framework_io": true,
    "tickets": 0,
    "application_bytes": 32,
    "record_size_limit": 0,
    "certificate_compression": false
  },
  "measurement": {
    "samples": 8,
    "connections": 1,
    "warmups": 0,
    "timeout_ms": 10000,
    "failure_policy": "fixed-attempts",
    "flush_grace_ms": 500,
    "ca_cpu": -1,
    "pin_cores": false,
    "perf": false
  },
  "lookup": {
    "enabled": true,
    "object_file": "../pki/netem/server-chain.pem",
    "cache_mode": "empty",
    "snapshot_file": null
  }
}
```

경로는 프로필 파일 기준입니다. warm 조건에는 `cache_mode`를 `fixed-snapshot`으로 바꾸고 `snapshot_file`에 생성한 파일을 지정합니다. `empty`에 snapshot을 지정하거나 `fixed-snapshot`에서 생략하면 설정 오류입니다. 조회가 활성화되면 출력의 시나리오 이름은 프로필 이름과 관계없이 `synthetic-lookup-plus-standard-tls`로 고정됩니다.

### 조회 없는 표준 TLS 프로필

같은 runner로 순수 표준 TLS를 격리 실행할 때는 조회를 명시적으로 끕니다.

```json
{
  "name": "standard-tls-netem",
  "pki": "../pki/netem",
  "tls": {
    "version": "TLS1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "group": "secp256r1",
    "signature": "ecdsa_secp256r1_sha256",
    "server_name": "localhost",
    "mutual_auth": false,
    "compatibility_ccs": true,
    "framework_io": true,
    "tickets": 0,
    "application_bytes": 32,
    "record_size_limit": 0,
    "certificate_compression": false
  },
  "socket": {
    "tcp_nodelay": true,
    "send_buffer": 65536,
    "receive_buffer": 65536
  },
  "lookup": {"enabled": false},
  "measurement": {
    "samples": 2,
    "connections": 1,
    "warmups": 0,
    "mode": "timing",
    "timeout_ms": 10000,
    "failure_policy": "fixed-attempts",
    "flush_grace_ms": 500,
    "pin_cores": false,
    "perf": false
  },
  "technique": {"name": "standard-tls"}
}
```

`lookup.enabled=false`에서는 `object_file`, `cache_mode`, `snapshot_file`을 요구하지 않습니다. 모의 CA 자식·소켓·원자료, lookup 원자료, snapshot을 만들지 않고 client/server 두 TLS 역할만 attempt 참여자로 기록합니다. 위 예제는 CPU 고정과 perf를 명시적으로 끈 기능 확인용이며 통제한 성능 실행 프로필이 아닙니다.

`failure_policy` 기본값은 `fail-fast`입니다. 첫 실패 뒤 남은 요청 수는 `not_attempted`로 남깁니다. `fixed-attempts`는 회수 완료가 확인된 attempt 실패 뒤에도 다음 attempt를 시작하지만, 치명적인 환경·셋업 실패 뒤에는 남은 수를 실행하지 않습니다. 실패를 성공 표본으로 채우는 자동 재시도는 없습니다.

## net-profile과 네트워크 격리

`net-profile`은 프로필과 별도인 엄격한 JSON입니다. 조회 프로필은 네 방향을 모두 적어야 합니다.

```json
{
  "type": "turtle-netem-profile",
  "schema": 1,
  "qdisc": "netem",
  "mtu": 1500,
  "offload": {"tso": false, "gso": false, "gro": false},
  "trace": true,
  "loss_seed": null,
  "paths": {
    "tls_c2s": {"delay_ms": 0, "loss_percent": 0, "limit_packets": 10000},
    "tls_s2c": {"delay_ms": 0, "loss_percent": 0, "limit_packets": 10000},
    "ca_c2s": {"delay_ms": 0, "loss_percent": 0, "limit_packets": 10000},
    "ca_s2c": {"delay_ms": 5, "loss_percent": 20, "limit_packets": 10000}
  }
}
```

조회가 꺼진 프로필은 다음처럼 두 TLS 방향만 적을 수 있습니다.

```json
{
  "type": "turtle-netem-profile",
  "schema": 1,
  "qdisc": "netem",
  "mtu": 1500,
  "offload": {"tso": false, "gso": false, "gro": false},
  "trace": true,
  "loss_seed": null,
  "paths": {
    "tls_c2s": {"delay_ms": 20, "loss_percent": 0, "limit_packets": 10000},
    "tls_s2c": {"delay_ms": 20, "loss_percent": 0, "limit_packets": 10000}
  }
}
```

호환을 위해 조회가 꺼진 실행에 기존 네 방향 net-profile을 입력할 수도 있지만, runner는 CA 두 방향을 활성 조건에서 제거하고 실제로는 두 TLS 방향만 만듭니다. 새 순수 TLS 설정에는 두 방향 형식을 사용합니다.

Python coordinator는 `unshare --user --map-root-user --net` 안에 topology를 소유합니다. 조회가 켜지면 client/server/ca/router 네 data network namespace와 네 veth 링크를 만들고 C++에 client/server/ca namespace FD를 전달합니다. 조회가 꺼지면 client/server/router 세 namespace와 두 veth 링크만 만들고 C++에는 client/server FD만 전달합니다. 두 경우 모두 자식은 namespace에 들어간 **뒤** listener와 socket을 만들며 router FD는 받지 않습니다. `/run/netns` 이름, host route, host qdisc, host interface는 바꾸지 않습니다. 실험 종료 때 observer, helper, namespace FD를 소유 목록으로 정리합니다.

router의 수신자 직전 egress에 활성 방향별 qdisc를 둡니다. 조회 실행은 네 곳, 순수 TLS 실행은 `tls_c2s`·`tls_s2c` 두 곳입니다. attempt마다 이전 qdisc와 큐를 지우고 같은 요청 정책으로 다시 만들며, setup/scenario/cleanup 단계의 readback을 `observation_id`로 연결합니다. MTU와 TSO/GSO/GRO는 요청뿐 아니라 실제 readback을 보존합니다. 요청과 실제값이 다르면 strict 실행은 실패합니다. 현재 확인한 tc 6.1 환경에서는 non-null `loss_seed`를 지원한다고 주장하지 않으며 setup 실패로 처리합니다.

netem의 `loss_percent`는 요청 정책입니다. qdisc `drops`는 phase 창에서 관측한 **skb drop** 집계이며, 특정 조회 요청의 손실 수나 물리 wire packet 수가 아닙니다. GSO/TSO/GRO 상태에 따라 skb 단위가 바뀔 수 있습니다. 소켓의 `TCP_INFO.total_retrans` 구간 차는 TCP 재전송 근거이며 qdisc drop과 단위가 다릅니다. `remote_lookup_duration_ns`도 CA 처리·입출력·대기·스케줄링을 포함하므로 순수 RTT라고 부르지 않고, CA 시간과 더해 이중 합산하지 않습니다.

## 실행 명령

먼저 이 커널과 설치 도구에서 user/network namespace, veth, qdisc, offload readback, AF_PACKET 관측을 만들 수 있는지 확인합니다.

```sh
python3 scripts/netem-study.py probe --output results/netem-probe
```

한 고정 조건을 실행합니다. `--samples`를 생략하면 프로필 값을 사용합니다. runner가 내부 `--network-manifest`를 만들고 FD를 전달하므로 사용자가 manifest나 FD 번호를 직접 만들지 않습니다.

```sh
python3 scripts/netem-study.py run \
  --build build \
  --profile configs/lookup.json \
  --net-profile configs/ca-loss.json \
  --samples 8 \
  --output results/lookup-run
```

승인된 고정 검증 묶음은 미리 만든 ECDSA P-256 3인증서 체인을 요구합니다. runner가 PKI를 몰래 만들거나 조건을 결과에 맞춰 바꾸지 않습니다.

```sh
scripts/make-pki.sh pki/netem ecdsa 3
python3 scripts/netem-study.py verify \
  --build build \
  --pki pki/netem \
  --output results/netem-verify \
  --require-supported
```

`--require-supported`는 지원되는 환경을 요구한다는 의도를 명시하고 기존 호출 표기를 보존합니다. 현재 `verify`는 이 옵션을 생략해도 지원 불가를 성공으로 바꾸지 않고 비0으로 끝냅니다. 옵션 유무가 검증 강도를 바꾸는 별도 모드는 아닙니다. `tests/integration/netem.py`의 positional 인자는 CTest용 helper 계약이며, 위 N05 사용자 명령을 대신하지 않습니다.

`verify`는 아래의 기존 조회 묶음을 그대로 실행합니다. 순수 TLS는 `run`에 `lookup.enabled=false` 프로필과 두 방향 net-profile을 전달해 재현합니다. 새 통합 시험 `tests/integration/pure_tls_netem.py`는 OpenSSL로 양방향 0ms와 20ms, loss 0, 조건별 2 attempts를 실행하고 해독·정리·보고 계약을 검사합니다. 이 시험을 포함한 최신 전체 반복 결과는 `docs/validation.md`의 G007 기록을 따릅니다.

검증 manifest는 실행 전 다음 조건을 고정합니다.

| 실행 | attempts | 조건 |
|---|---:|---|
| baseline | 8 | qdisc 없음 |
| zero | 8 | netem, 네 방향 delay/loss 0 |
| delay-20ms | 8 | CA→client만 20ms, 진단용 시간 보존 |
| tls-only-20ms | 8 | TLS server→client만 20ms, 경로 선택성 확인 |
| loss-ca-s2c-5ms-20pct | 64 | CA→client 5ms·20%, 나머지 0 |
| timeout-ca-s2c-1000ms | 3 | CA→client 1000ms, attempt timeout 100ms |
| warm-hit-request0 | 1 | fixed snapshot hit, 응용 조회 요청 0건 |

고정 loss gate는 64 attempts 원장, 양의 qdisc drop, 같은 CA 흐름의 양의 `total_retrans` 차이, packet flow 근거를 모두 요구합니다. 하나라도 0·누락이면 조건을 바꾸거나 횟수를 늘리지 않고 `validation-unproven`으로 끝냅니다. `verify`의 exit 0은 이 gate를 포함한 묶음 성공, exit 1은 실행 또는 검증 불충분, exit 2는 지원·셋업 불가입니다.

## CA 계측과 완료 상태

모의 CA는 public TLS `Role`을 확장한 가짜 서버가 아니라 별도 참여자입니다. 전용 `Meter`, heap tracker, TCP stream, `ca.jsonl`을 가집니다. CA process 경과·스레드 CPU·입출력 구간·대기 구간·heap은 TLS와 독립적으로 남깁니다. lookup 사건을 읽을 때 클라이언트 TLS `Meter`의 같은 perf 그룹을 읽으므로 lookup용 perf 그룹을 중복 생성하지 않습니다. 엔드포인트마다 perf 그룹은 하나뿐입니다.

## 2026년 10월 15일 고정 검증 결과

`results/mock-ca-goal/netem-verify-final/verification-manifest.json`은 `status=complete`입니다. runner가 고정한 공개 객체는 ECDSA P-256 3인증서 PEM 1,890바이트, `fnv1a64:58fddee27893d105`였습니다.

- baseline, zero, CA→client 20ms, TLS server→client 20ms가 각각 8/8 성공했고, 각 실행의 integrity gate가 통과했습니다.
- N05는 결과를 보고 바꾸거나 다시 돌리지 않고 정확히 한 번 실행했습니다. CA→client 5ms·20% loss에서 64/64 attempts가 성공했고, scenario qdisc drop 차이 합계 94와 CA `TCP_INFO.total_retrans` 차이 합계 58을 관측했습니다.
- N05 trace에는 AF_PACKET `record_kind=packet` 행이 4,148개 있습니다. router veth의 ingress/egress에서 같은 통신이 중복 관측될 수 있으므로 4,148개 물리 패킷이나 고유 패킷이라고 부르지 않습니다.
- timeout 조건은 의도대로 실행 자체가 exit 1이었고 3/3 attempts가 timeout으로 보존됐습니다. 9개 missing artifact와 missing phase window도 0이나 성공으로 바꾸지 않았습니다. 전체 `verify` manifest는 이 예상 실패를 timeout gate 통과로 판정했습니다.
- warm hit은 1/1 성공했고 lookup과 CA의 응용 `request_count=0`이었습니다. TCP 준비 packet의 존재와 응용 조회 요청 0건을 구별했습니다.
- 일곱 조건 모두 host network identity unchanged, 소유 helper 회수와 namespace/pipe FD 닫힘을 증명했습니다. MTU 1500 및 TSO/GSO/GRO off 실제값도 요청과 일치했습니다.

이 검증은 합성 조회 기반과 stock TLS가 손실을 겪는 정상 실행을 증명합니다. 실제 인증서 압축·생략·캐싱 기법의 구현이나 성능 이득은 증명하지 않습니다.

보존한 원자료를 최신 보고 도구로 다시 처리해 일곱 조건별 보고서와 합산 보고서를 만들었습니다. `report-final/lookup-summary.json`은 requested=started=100, success=97, timeout=3과 attempt/connection 행 각 100개를 보존합니다. 성공한 network attempt는 setup/scenario/cleanup의 begin/end **정확히 여섯** observation 참조, host unchanged와 owned cleanup이 모두 확인될 때만 비교 적격입니다. timeout 세 건은 결과 분포로 승격하지 않습니다.

G005의 구현·고정 실행·보고를 완료했습니다. 이어서 G006에서 전체 57개 시험을 각각 20회 실행해 총 1,140회 모두 통과했고, 정적 검사와 독립 코드·구조 검토도 완료했습니다. 이 검증 완료는 합성 조회 기반의 기능·기록·보고 계약에 한정됩니다. 실제 인증서 생략·압축·캐싱 기법이나 성능 이득을 증명하지 않습니다.

G007에서는 위 고정 조회 묶음이나 N05를 다시 실행하지 않고, 조회가 꺼진 0ms·20ms 순수 TLS 원자료를 별도로 보존했습니다. 최신 전체 58개 시험은 각각 20회 통과했습니다. `verify`의 범위와 기존 조회 검증 수치는 바뀌지 않았습니다.
