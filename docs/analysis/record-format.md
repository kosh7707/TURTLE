# 실행 명세와 사건 계약

새 계약은 문자열 값으로 식별합니다. 엔드포인트 설정은 `turtle-message-run/1`, 직접 준비 제어는 `turtle-message-control/1`, 사건은 `turtle-message-events/1`, manifest는 `turtle-message-manifest/1`입니다. 구형 필드나 다른 형식을 추측해서 읽지 않습니다. 엔드포인트 설정의 알 수 없는 필드는 오류입니다.

독립 장비에서는 각 역할에 다음 명세를 만들고 해당 실행 파일에 전달합니다. run_id와 공유 시나리오·인증·그룹·연결 수·응용 크기는 양쪽에서 같아야 합니다. 서버 주소는 수신 주소, 클라이언트 주소는 서버의 접속 주소입니다. 경로는 각 장비의 로컬 경로입니다.

```json
{
  "contract": "turtle-message-run/1",
  "run_id": "experiment-unique-id",
  "pki": "pki/default",
  "output": "results/my-client",
  "address": "127.0.0.1",
  "port": 44330,
  "control_port": 44331,
  "scenario": "client-request",
  "depth": "black-box"
}
```

| 선택 필드 | 기본값·의미 |
|---|---|
| scenario | `client-request`; `handshake`, `server-ping`, `finished-ping` |
| mutual_auth, group | false, `P-256`; ML-KEM 구현은 `ML-KEM-768` |
| depth | `black-box` 또는 `white-box` |
| records, send | `preserve` / `bundle`, `flight` / `server-hello-first` |
| connections, warmups | 1, 0; 각각 측정 연결과 준비 연결 수 |
| client_bytes, server_bytes | 32, 32; 검증 가능한 결정적 응용 바이트 수 |
| record_size, max_message | 16384, 1048576; 평문 레코드 상한과 논리 메시지 용량 |
| event_capacity, io_chunk | 100000, 0; 사건 배열 용량과 시험용 I/O 호출 상한 |
| timeout_ms, seed | 30000, 1; TCP·제어·시나리오의 소켓 대기 시한을 만드는 기준과 보존하는 실험 seed |
| thread_cpu | true |
| perf_counters, allocations, stream | false; 명시적으로 켜는 추가 관측 |
| cpu_samples, kernel | false; 외부 수집 요청 표지. 실제 가용성은 수집기 산출물에서 확인 |
| external_peer | false; 외부 TLS와 상호운용할 때 제어 연결 생략 |
| lookup_address, lookup_port | `127.0.0.1`, 44332 |
| lookup_sha256, lookup_size, lookup_snapshot | digest가 있으면 합성 객체 준비; 기본 크기 4096, 저장본 경로가 있으면 로컬 고정 바이트 사용 |
| network_condition | 로컬 기본값 `local-unshaped`; netem 실행기는 검증한 명세의 해시를 전달 |

`listener-preparation`은 서버의 데이터 수신 소켓을 준비하는 사건이며 연결 ID는 0입니다. 연결별 `transport`와 구분해 최초 준비에 한 번만 포함합니다.

`timeout_ms`는 진행 중인 native 암호 연산을 강제로 선점하는 장치가 아닙니다. TCP·제어 경로와 `Execution`은 각각 마감 시각을 만들고 소켓 대기에서 확인합니다. 명세의 개별 용량 제한을 만족하더라도 레코드 수·출력 배치·캡처·사건 배열의 모든 조합이 사전 보장되지는 않습니다. [버퍼 설계](../design/architecture.md)를 함께 읽습니다.

실행당 컨텍스트 하나입니다. 준비 연결과 측정 연결 모두 새 TCP와 연결 상태를 사용하지만 같은 TLS 컨텍스트를 재사용합니다. 제어 연결은 준비 상태와 공유 조건, 연결별 성공 완료를 확인합니다. 확인용 TLS 접속을 추가하지 않습니다. `ready` 파일은 포트를 열었다는 표시이며 TLS 인증 성공 표시가 아닙니다.

## 산출물

manifest의 공개 인증서 출처는 파일별 status·bytes·sha256을 보존합니다. 역할에 필요하지 않아 없는 파일은 missing·null로 남기며 빈 파일의 해시나 실제 0바이트로 기록하지 않습니다. 개인키 내용은 산출물에 넣지 않습니다.

각 역할 디렉터리에는 `run.json`, `manifest.json`, `events.jsonl`, 연결별 `N.result.json`을 둡니다. 스트림을 켜면 `N.tx.bin`·`N.rx.bin`에 성공한 소켓 송수신의 원본 TLS 바이트를 저장합니다. `N.tx.plain.bin`·`N.rx.plain.bin`은 각각 보호 입력과 인증 복호화 출력의 연결별 평문 연결본입니다. TLS 레코드 헤더·padding·tag는 평문 연결본에 들어가지 않습니다.

외부 실행기의 `launch.json`은 바이너리 SHA-256, 인자, 프로세스와 종료 코드를 기록합니다. `build-manifest.json`은 빌드 당시 소스, 컴파일 명령, 고정 의존성 원본·패치·정적 라이브러리와 실행 파일 해시를 보존합니다. 이 파일은 `scripts/build.sh`에서 생성합니다. 직접 CMake만 사용하면 자동으로 출처를 추정하지 않으며 `scripts/provenance.py BUILD DEPS`를 빌드 직후 실행해야 합니다.

사건에는 run_id, context_id, role, connection_id, sequence와 message_id·record_id·batch_id가 있습니다. 메시지와 레코드 ID는 송신자별 순서이며 서버 송신은 상위 32비트에 표시합니다. 양쪽 엔드포인트가 같은 송신 메시지와 레코드를 같은 ID로 식별합니다. ID는 실행·컨텍스트·연결과 함께 읽습니다. 배치 ID는 로컬 송신 배치입니다. 수신만으로 상대 `send` 배치를 추측하지 않습니다.

`stream_offset/bytes`는 레코드·암복호화·소켓 I/O·배치 사건에서 TLS 스트림 범위입니다. `assemble/process` 사건에서는 같은 필드가 해당 `message_id` 안에서 생산·소비한 조각의 시작과 길이를 뜻합니다. 조회 사건의 bytes는 합성 객체 바이트 수입니다. 범위는 사건 종류와 함께 읽습니다. `plain_offset/plain_bytes`는 메시지·레코드 관계 사건에서 복호화 평문 연결본의 범위입니다. 반개구간 `[offset, offset+bytes)`을 사용합니다. 메시지와 레코드는 이 평문 범위의 교집합으로 연결합니다. 여러 메시지가 공유한 레코드의 암복호화 비용이나 여러 레코드가 공유한 소켓 쓰기 비용은 한 번 기록합니다. 각 메시지에 나누어 붙이지 않습니다.

시각·CPU·계수·ID·바이트 위치는 JSON 정수입니다. 정밀도가 작은 부동소수점으로 원자료를 읽으면 안 됩니다. `message`·`record` 관계 사건의 begin/end는 null입니다. 이들의 시각을 0으로 채우거나 처리 시간을 중복해서 만들지 않습니다. `batch`는 제출 전체의 부모 구간이며 내부 send/wait와 더하지 않습니다.

관측 상태는 `available`, `not-collected`, `unsupported`, `missing`으로 구별합니다. 값의 null은 실제 0이 아닙니다. PMU의 raw 계수와 실행·활성 시간을 함께 남기며 다중화 계수를 정확한 시간으로 환산하지 않습니다. 할당 값은 호출 시점의 누계·현재값·수명 최고값입니다. 실패하면 원인과 이미 기록한 사건을 남기고 그 프로세스의 표본을 성공 분포에서 제외합니다.
