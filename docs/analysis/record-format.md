# TLS 원자료 형식 3

각 표본 폴더에서 클라이언트와 서버는 각각 자신의 파일을 씁니다. 모든 원자료 파일은 자원 제한을 적용하기 전에 엽니다. 측정 중에는 미리 확보한 버퍼만 사용하고, 원자료의 JSON 변환과 파일 쓰기는 측정이 끝난 뒤에 합니다. 제어 연결의 준비 JSON은 측정 전에 교환합니다.

## 파일

- `client.jsonl`, `server.jsonl`: 첫 줄은 `sample`, 나머지는 `event`입니다.
- `<역할>.conn-<연결 번호>.sent.bin`, `received.bin`: 실제 성공한 송신·수신 바이트입니다. 위치는 각 연결과 방향마다 0부터 셉니다.
- `<역할>.keys.log`: 줄마다 NSS 형식의 키 로그를 보관합니다. 줄 끝은 줄바꿈 하나를 보장합니다.
- `<역할>.context.bin`: 다음 프로세스에 전달할 구현체 상태입니다.
- `<역할>.plaintext.bin`, `plaintext.jsonl`: 선택적인 라이브러리 알림 원문과 색인입니다. 색인은 연결, 방향, 내용 종류, 원문 파일 내 위치와 길이를 담습니다. 이것은 네트워크 바이트 위치가 아닙니다.

`plaintext.jsonl`은 추적 모드에서 어댑터가 제공한 평문 알림의 종류와 순서를 대조하는 메시지 대조 기준입니다. 색인에는 계측 스냅샷이나 시각 필드가 없으므로 메시지의 시작·완료 시각, 지속 시간이나 비용을 계산할 수 없습니다. 지원하지 않는 어댑터의 부재를 빈 메시지나 0시간으로 바꾸지 않습니다.

조회 시나리오는 TLS 기록과 별도인 다음 파일을 더 만듭니다. TLS는 schema 3, 조회·CA·원장 형식은 각각 schema 1입니다.

- 실행 루트의 `attempts.jsonl`: 상위 프로세스가 먼저 쓰는 요청·시작·최종 상태 원장입니다.
- 표본 폴더의 `lookup.jsonl`, `ca.jsonl`: 각각 `certificate-lookup`, `mock-ca` 형식의 `schema=1` 서비스 기록입니다. TLS 선언·검증 값을 가짜로 채우지 않습니다.
- `lookup-<연결>.sent.bin`, `.received.bin`, `ca-<연결>.sent.bin`, `.received.bin`: 44바이트 전송 머리를 포함한 실제 성공 바이트입니다. TLS 스트림과 섞거나 TLS 해독기에 넣지 않습니다.
- 실행 루트의 `network-manifest.json`, `network-provenance.json`, `network-observations.jsonl`, `packets.jsonl`: 요청한 격리 조건, schema 2 출처·실제 적용값 재조회, 단계별 qdisc 관측, 선택 패킷 추적입니다.
- 보고 출력의 `lookup-summary.json`: 원장·조회·CA·TLS·TCP·네트워크 관측을 ID로 연결한 자료입니다.

## schema 3의 실행·출처 계약

TLS JSONL schema 3은 공개 어댑터 ABI 3·측정 계약 개정 4와 별도입니다. TLS 판독기는 schema 3의 측정 계약 개정 3·4를 받습니다. 개정 3 자료는 기록된 종료점 그대로 재분석하고 개정 4와 같은 비교 조건으로 합치지 않습니다. 다른 형식은 명시적인 오류로 끝냅니다.

| 필드 | 의미 |
|---|---|
| `run_id`, `context_id` | 양쪽이 준비 단계에서 합의한 실행·컨텍스트 식별자입니다. 사건에도 남기며 연결 순번과 함께 결합합니다. |
| `clock_domain` | 자기 단조 시계 영역입니다. 기본은 Linux boot ID이며 같은 문자열만으로 교정 정확도를 주장하지 않습니다. |
| `scenario`, `control_protocol` | 합의한 공유 시나리오와 제어 프로토콜 2입니다. 로컬 파일·CPU·절대 시각은 교환하지 않습니다. |
| `preparation.version`, `stage` | 준비 상태 형식 1과 마지막 도달 단계입니다. 준비 상태 형식은 TLS 측정 계약 개정과 독립적입니다. 새 TLS 실행은 측정 계약 개정 4이며, 없는 과거 준비 자료는 미관측으로 읽습니다. |
| `preparation.control_connected`, `scenario_agreed`, `local_prepared`, `peer_prepared` | 제어 TCP 접속, 공유 시나리오 합의, 자기·상대 준비 확인을 구별합니다. 준비 완료가 최종 TLS 성공을 대신하지 않습니다. |
| `preparation.control` | 제어 소켓의 실제 로컬·상대 주소와 `tcp/ipv4` 전송 경로입니다. 연결하지 못했으면 null이며 물리 NIC 통과는 `unobserved`입니다. |
| `preparation.local`, `peer` | 자기·상대의 준비 요약입니다. 아직 확인하지 못한 요약은 null입니다. 구현·연결 방식·모드·계측 지원과 준비 범위를 담고 파일 경로·CPU 번호·시각은 보내지 않습니다. |
| `adapter_connection.mode` | `builtin` 또는 `module`입니다. `artifact`는 자기 실행 파일 또는 모듈의 경로입니다. |
| `adapter_connection.tls_linkage` | 어댑터 연결과 별개인 TLS 라이브러리의 정적·동적 링크입니다. 선언에서 확인할 수 없으면 `unavailable`입니다. |
| `adapter_connection.module_load` | 모듈에서 실제 관측한 로드는 `observed`, 내장 연결은 `not_applicable`, 관측 실패는 `missing`입니다. |
| `adapter_connection.pre_entry_loading` | 항상 `unobserved`입니다. 프로그램 진입 전 로더 비용을 재지 않습니다. |
| `config.cpu`, `config.implementation` | 자기 CPU 선택과 실제 함수표의 구현 이름입니다. 상대 파일·CPU 설정은 없습니다. |
| `config.local_boundary_observer` | 로컬 실행기가 준비·정리 경계에서 관측 확인을 수행했는지 표시합니다. |
| `connections[].flow` | 자기 TLS 소켓의 실제 로컬·상대 IPv4 주소와 포트입니다. 제어 연결의 바이트는 포함하지 않습니다. |
| `failure_phase` | 정상 실행을 완료하지 못한 단계입니다. `invalid_reason`과 함께 남깁니다. |

완료 기록 뒤 상대의 확인을 받지 못하면 `<역할>.failure.json`이 실행·컨텍스트 ID와 정리 실패 이유를 보존합니다. 보고서는 이 표식도 읽고 양쪽 성공으로 승격하지 않습니다. `execution.json`과 `attempts.jsonl`은 외부 로컬 실행기의 결과이며 수동 실행의 필수 입력은 아닙니다. 조회 보고서는 요청한 시도 수와 실패 분모를 보존하기 위해 외부 실행기의 `attempts.jsonl`을 필수로 읽습니다.

서비스 원자료의 형식은 schema 1을 유지하되 `run_id`, `context_id`, `clock_domain`을 추가합니다. TLS schema 3과 결합할 때 조회·서비스·양쪽 TLS의 실행 ID를 확인합니다. CA 시간은 CA 시계 안의 차이로 계산하며 클라이언트의 단조 시각을 빼지 않습니다.

## 표본 머리

`schema`, `sample`, `batch`, `role`, `pid`, `mode`, `valid`, `invalid_reason`, 프로필·환경 해시를 담습니다. `config`, `environment`, `capabilities`, `declaration`, `calibration`, `connections`에는 공통 값 구조의 모든 설정과 관측 결과를 보존합니다. 비밀 키 파일 경로는 설정의 일부이며 키 파일 내용 자체는 JSON에 넣지 않습니다.

`measurement_contract_revision`은 필수이며 새 실행은 4를 기록합니다. 개정 4의 `end_sequence`는 시나리오의 마지막 성공 `CALL_END`입니다. 개정 3은 과거 실행이 기록한 인증 결과 조회 완료 또는 응용 완료 표식 경계를 보존하며 소급 변경하지 않습니다. 키 공유 생성은 핸드셰이크 측정 안에 있고, 성공 I/O 반환의 프레임워크 캡처는 I/O 구간에 포함합니다. 시행마다 새 TCP를 만들고 `connections[].end_sequence`로 시나리오 종료 사건을 지정합니다. 저장 형식, 측정 의미와 ABI의 버전은 서로 별개입니다.

`declaration.read_ahead`는 TLS 수신 선행 정책의 선택 불리언이고 `declaration.read_ahead_note`는 근거와 한계입니다. `false`는 현재 레코드의 필요 범위를 넘어 다음 레코드를 선행 수신하지 않는 정책입니다. 성공 `recv` 횟수를 두 번으로 고정하는 값이 아닙니다. 필드 부재와 `mock`의 `null`은 `false`로 바꾸지 않습니다.

`config.perf_scope`는 요청한 성능 카운터 범위 `user` 또는 `user+kernel`입니다. TLS 머리글과 조회·모의 CA 서비스 머리글의 `capabilities`는 `perf_requested_scope`, `perf_status`, `perf_effective_scope`, `perf_failure_stage`, `perf_error_number`, `perf_note`를 가집니다. `perf_status`는 `disabled`, `available`, `unsupported` 중 하나이고 기존 `capabilities.perf`는 `available`일 때만 `true`입니다. `available`일 때만 실제 범위가 요청 범위와 같은 문자열이며, 나머지 두 상태의 실제 범위는 `null`입니다. 이 `null`은 알려진 비활성 또는 미지원이며 필드 누락의 알 수 없음과 다릅니다.

`capabilities.perf_effective_scope` 키가 있으면서 값이 `null`인 경우와 키 자체가 없는 경우를 구별합니다. 명시적 `null`은 `disabled` 또는 `unsupported`에 따라 실제 범위가 없다는 알려진 상태입니다. 성능 카운터 안정 필드 중 일부만 있는 부분 선언에서 이 키가 없으면 실제 범위를 알 수 없으며, 보고 단계에서도 키를 생략합니다. 성능 카운터 조건이 누락되면 자동 비교에서 제외하며 알려진 비활성 상태로 추정하지 않습니다.

미지원 설정은 `perf_failure_stage`에 `cycles_open`, `instructions_open`, `reset`, `enable`, `initial_read` 중 해당 단계를 남기고 `perf_error_number`에 errno를 남깁니다. 이 두 필드와 `perf_note`는 실패 진단이지 안정 실험 조건이 아닙니다. 비활성이면 실패 단계와 errno는 `null`입니다.

`environment.perf_event_paranoid`는 정수 또는 `null`이고, 읽지 못했거나 정수가 아니었으면 `perf_event_paranoid_reason`을 남깁니다. `environment.cpu_topology[]`는 `cpu`, `package_id`, `core_id`, `thread_siblings`를 담습니다. `thread_siblings=null`은 목록 미관측, 빈 목록은 관측했지만 형제 없음입니다. 형제 항목은 `cpu`와 선택 `online`을 가지며 온라인 상태를 알 수 없으면 `online=null`입니다. 위상은 affinity 허용 범위 밖 형제도 포함합니다.

`clock_start`, `clock_end`는 실제 시각과 단조 시각의 대응 관측입니다. `observation_level`, `incomplete`, `perf_complete`, 저장·복원한 상태 크기, 고정한 CPU도 남깁니다. 버퍼 공간이 부족하면 `capture_dropped`가 증가하고 표본은 무효로 저장됩니다. 넘친 데이터를 일부만 잘라 성공으로 표시하지 않습니다.

`availability`는 `tls_stream`, `io_events`, `kernel_receive_events` 각각에 대해 `available` 불리언과 `reason`을 가집니다. 콜백 경로의 스트림·I/O는 사용할 수 있습니다. 라이브러리 직접 소켓 경로의 세 항목은 `native_socket_io_not_observed` 이유로 사용할 수 없습니다. 콜백에서도 커널 시각 설정을 준비하지 못했으면 `kernel_timestamps_not_configured`입니다. 가용성은 수집 통로의 지원·설정 상태이며 사건 발생 횟수가 아닙니다. 특히 `kernel_receive_events.available=true`만으로 실제 수신 시각이 있었다고 말하지 않습니다. `raw_timestamp_ns`가 있는 사건이 발생 증거입니다.

`config.channel_observer`는 프로필의 `measurement.channel_observer`를 재현하며 필드 부재의 기본값은 `true`입니다. `false`이면 콜백 I/O 자체는 유지하지만 `observation_level`은 `observer-disabled`이고 위 세 가용성 이유는 모두 `channel_observer_disabled`입니다. 소켓의 `kernel_timestamps=true`와 수집 사건 가용성은 같은 뜻이 아닙니다. 키 로그·평문 파일, CALL/WAIT 사건과 성능 카운터 설정도 관측자 끔만으로 꺼지지 않습니다.

`connections[*].primary_window`는 역할의 기존 주 측정 구간을 만들 수 있는지와 이유를 보존합니다. 라이브러리 직접 소켓 또는 관측자 끔 경로의 클라이언트는 호출 시작·끝을 볼 수 있어 사용할 수 있습니다. 같은 두 경로의 서버는 첫 성공 프레임워크 수신을 볼 수 없어 `available=false`, `reason=server_first_receive_not_observed`이며 `start_sequence`는 `null`입니다. 기능적으로 성공한 연결도 이 지표는 사용할 수 없을 수 있습니다.

`connections[*].socket`에는 TLS 이전에 다시 읽은 `nonblocking`, `tcp_nodelay`, `send_buffer`, `receive_buffer`, `kernel_timestamps`를 저장합니다. 버퍼 크기는 커널의 실제 조회값이며 `config.socket_send_buffer`와 `config.socket_receive_buffer`의 요청값과 다를 수 있습니다. 관측하지 않은 경우에는 객체 대신 `null`이고, 필드가 누락되면 요청값으로 대신하지 않습니다.

`loaded_context_hash`는 실제 셋업 입력 바이트의 FNV-1a 지문입니다. 입력이 비었으면 빈 문자열이며, 비어 있지 않으면 `loaded_context_size`와 함께 입력 상태를 식별합니다. 각 엔드포인트가 자기 입력 파일을 준비 단계에서 한 번 읽습니다. 외부 반복은 같은 파일을 지정할 수 있습니다. 저장 결과 파일은 이 입력과 다를 수 있습니다. 지문은 보안 검증값이 아닙니다.

## 사건

각 줄에 표본·묶음·역할·프로필 해시·환경 해시와 연결 번호, 사건 순번, 종류, 관측 위치, 호출 종류·번호를 붙입니다. 시간은 나노초입니다. 사이클·명령어·성능 카운터 실행 시간·힙을 얻지 못하면 `null`입니다. 실제로 관측한 0과 다릅니다.

`output_flush`의 `CALL_BEGIN`·`CALL_END`에서 `requested`는 그 호출 직전 출력 버퍼의 미제출 바이트입니다. 종료 사건의 `result`·`transferred`·`system_error`는 한 번의 소켓 제출이 반환한 `IoResult`이며, 같은 `call_id`의 `IO_SEND_RETURN`과 일치합니다. `IoStatus::Ok=0`은 TLS API의 `Step::Complete=2`와 다른 열거형입니다. 부분 제출 뒤 남은 바이트는 다음 호출에 요청하며 `WantWrite`의 0바이트 반환은 성공한 전체 제출을 뜻하지 않습니다.

2026-11-12 의도 점검에서 이 호출 종료의 I/O 반환값이 0으로 기록되던 오류를 수정했습니다. 수정 전 자료의 `output_flush` 호출 필드만으로 실제 제출량·상태를 판단하지 말고 같은 호출의 I/O 사건을 확인해야 합니다. 기존 원자료를 소급 수정하지 않았고 ABI·schema·측정 계약은 바꾸지 않았습니다. [재현 근거](../project/intent-audit.md)를 참고하십시오.

### 조회·CA 서비스 사건

서비스 기록은 `header`, `event`, `connection_summary`, `footer` 순서입니다. 사건은 시도·표본, 0부터 세는 연결 번호, 요청 ID 1, 순번, 참여자, 스트림 ID, 단조 시각과 스레드 CPU를 가집니다. 주요 사건은 `CACHE_LOOKUP`, `HIT`, `MISS`, `CACHE_INSERT`, `REQUEST_BEGIN`, `RESPONSE_COMPLETE`, `USABLE_OBJECT`, `SCENARIO_BEGIN/END`, `CA_PROCESS_BEGIN/END`, 입출력과 대기의 시작·끝입니다.

`RESPONSE_COMPLETE`는 마지막 응답 바이트를 받은 경계입니다. `USABLE_OBJECT`는 원본 바이트 비교와 캐시 삽입 뒤의 경계입니다. 둘 사이를 같은 사건으로 취급하지 않습니다. 캐시 적중에는 전송 경로 요청이 없으므로 `request_count=0`이며 원격 조회 시간은 관측된 0이 아니라 해당 없음 `null`입니다.

각 연결 요약은 객체 ID·크기, 캐시 적중, 요청 수, `tcp_start`/`tcp_end`, 산출물 상태와 힙 도메인을 가집니다. `logical_cache_bytes`, `cache_capacity`, `reference_bytes`, `framework_reserved_bytes`는 서로 다른 설명값입니다. 힙 합계에 다시 더하지 않습니다. 시간 모드 힙, 미지원 TCP_INFO, 시간 초과 때문에 없는 경계는 이유가 있는 `null`입니다.

`attempts.jsonl`은 `run_config`, `attempt_started`, `attempt_final`, `run_summary` 행을 씁니다. 강제 종료로 자식 파일이 없어도 상위 프로세스가 먼저 내구성 있게 기록한 시작 시도는 사라지지 않습니다. `final_status`는 `success`, `timeout`, `error`, `incomplete`, `not_attempted`를 구별하고 최초 `failure_phase`, 주 이유, 후속 이유, 외부 실행기 시계의 로컬 절대 기한, 기록 완료 유예, 참여자, 연결, 산출물 상태, 네트워크 관측 ID를 보존합니다.

패킷 추적의 관측 단위는 router veth에서 본 커널 패킷 버퍼입니다. 물리 패킷이라고 부르지 않습니다. qdisc 통계는 단계 관측의 공유 집계이며 연결 행마다 복제해 합산하지 않습니다. 소켓별 TCP 카운터 차이와 별도로 읽습니다.

시간 초과 시도와 누락 산출물은 원장에 보존합니다. `network-observations.jsonl`의 끝나지 않은 셋업·시나리오·정리 경계는 `partial-window`와 `:missing` 관측 ID로 남깁니다. 이 결측을 qdisc 0이나 성공한 경계로 바꾸지 않습니다.

성공한 네트워크 시도의 비교 적격성을 판정하려면 원장의 참조가 `<attempt>:setup:begin/end`, `scenario:begin/end`, `cleanup:begin/end`의 정확히 여섯 개여야 합니다. 각 참조는 같은 시도·단계·경계의 실제 관측과 일치하고 qdisc 및 요청한 추적 근거를 가져야 합니다. 호스트 네트워크 불변과 소유 보조 프로세스·FD 정리도 별도로 확인합니다. 중복·누락·다른 시도 참조는 보수적으로 실패입니다.

`attempts.jsonl`의 JSON 행·형식·분모가 잘못되면 보고를 오류로 끝냅니다. 조회 분석은 원장이 없는 경우에도 오류로 끝나며 성공 파일 수로 분모를 대신하지 않습니다. 수동 TLS 실행은 원장 없이 양쪽 원자료를 직접 지정할 수 있습니다.

입출력의 `requested`, `transferred`, `stream_begin`, `stream_end`는 요청 길이, 성공 길이, 반열린 바이트 구간입니다. `result`, `system_error`를 그대로 보관합니다. 순번과 구간은 호출자가 부여한 값을 보존합니다.

I/O 반환 사건의 스냅샷은 반환 사건 공간 예약, 성공 바이트가 있을 때의 스트림 복사·첫 수신 순번 갱신·`KernelRx` 공간 예약 뒤에 한 번 읽습니다. 반환 사건과 `KernelRx`는 같은 스냅샷을 갖고, 사건 순번·연결·스트림 구간·커널 원시 시각은 그대로 보존합니다. 이 순서는 반환 바이트 캡처를 I/O 구간으로 분류하기 위한 것이며, 관측 비용 전체를 제거했다는 뜻이 아닙니다.

커널 관측은 `raw_timestamp_ns`, `timestamp_id`, `timestamp_coverage_exact`를 별도로 담습니다. 커널 시각을 단조 시각으로 가장하거나 개별 바이트의 정확한 도착 시각으로 확대 해석하지 않습니다.

## 주의

키 로그에는 연결의 비밀값이 들어갑니다. 프로젝트 시험용 인증서와 통신에만 사용하십시오. 기록기는 TLS를 해석하지 않으며 해독 성공이나 실제 TLS 실행 성공을 보장하지 않습니다.

## 오프라인 해석과 요약

- `turtle-interpret <역할>.jsonl <출력>.json`은 저장한 양방향 스트림과 해당 역할의 키 로그를 읽습니다. TLS_AES_128_GCM_SHA256만 해독하며, 핸드셰이크 키에서 응용 데이터 키로 바뀌는 지점은 해당 방향의 Finished입니다. 누락된 키나 지원하지 않는 암호 방식은 해독 불가로 표시하고 레코드 구간을 보존합니다.
- 라이브러리 직접 소켓 경로의 빈 `.sent.bin`·`.received.bin`은 관측된 0바이트 TLS나 해독 성공이 아닙니다. 해석 결과는 `availability.tls_stream.available=false`, 빈 레코드·메시지 배열과 `decryption_complete=false`를 남깁니다.
- `observer-disabled`의 빈 스트림도 같은 방식으로 `channel_observer_disabled`, `decryption_complete=false`를 남깁니다. `config.channel_observer` 필드가 없는 과거 콜백 원자료는 관측자 켬으로 읽고 기존 해독 의미를 유지합니다.
- 해독 결과의 `plaintext_fragments`는 레코드 안의 평문 위치입니다. `record_stream_ranges`는 그 메시지를 담은 레코드 전체의 전송 구간입니다. 암호문 안에서 메시지에 해당하는 정확한 바이트 구간이라고 주장하지 않습니다. 한 레코드에 여러 메시지가 있으면 `bundled`로 표시합니다.
- `event_annotations`는 성공한 입출력의 바이트 구간과 레코드 전체 구간이 겹치는 메시지 이름입니다. 정확한 메시지별 연산 비용은 아닙니다.
- `turtle-report <원자료 파일 또는 폴더> <출력 폴더>`는 `summary.json`과 경험적 누적 분포 SVG를 만듭니다. 유효하지 않은 표본과 준비 연결은 요약에서 제외합니다.
- 개정 4의 기본 구간은 클라이언트 첫 핸드셰이크 호출 또는 서버 첫 성공 TLS 수신부터 각 시나리오의 마지막 성공 TLS API 반환까지입니다. `handshake`는 핸드셰이크, `client-request`는 클라이언트 수신·서버 송신, `server-ping`·`finished-ping`은 클라이언트 송신·서버 수신 완료로 끝납니다. 개정 3은 기록된 `end_sequence`를 그대로 사용합니다. 커널 사건은 구간 분할에서 제외하며 연산·입출력·대기·틈 합계가 전체와 같은지 검사합니다.
- 사이클·명령어는 표본의 `perf_complete`가 참이고 두 경계에서 값이 있을 때만 요약합니다. 힙 최고치는 구간 안의 사건이 보고한 `interval_peak` 중 최댓값입니다. 메모리·추적 모드의 시간은 `diagnostic_only`이며 성능 비교의 부트스트랩 대상이 아닙니다.
- 안정화 사분위수는 정렬 후 각 표본의 구간 가중치로 계산합니다. 표본을 여덟 번 복제한 기준과 일치합니다. 비교는 같은 역할·환경·모드·관측 수준·출발 상태끼리 하며 독립 재표집 2,000회와 고정 시드 1을 사용합니다. 같은 표본끼리 짝지은 차이의 검정은 아닙니다.
- 현재 요약은 보정 전 원자료입니다. 사용자 지정 대체 측정 구간, 계측 비용을 뺀 수치, 메시지 이름을 붙인 연산 토막별 통계는 아직 제공하지 않습니다. 원자료와 해석 결과를 남겨 후속 구현에서 계산할 수 있게 합니다.

해독 구현은 OpenSSL의 [HKDF API](https://docs.openssl.org/3.0/man3/EVP_PKEY_CTX_set_hkdf_md/)와 [EVP 암호 API](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/)를 사용합니다. 실제 TLS 시험에서는 같은 연결의 OpenSSL 메시지 알림과 해독한 핸드셰이크 종류를 방향별로 비교합니다.


## 시나리오와 내부 사건

`config.tls`에는 `scenario`, `send_policy`, `client_application_bytes`, `server_application_bytes`가 있습니다. `declaration`은 지원 시나리오·정책·내부 사건·범위 설명과 `source_version`, `source_url`, `technique`, `implementation`, `patch_hash`를 남깁니다. 연구 확장 실행은 `config.scenario_name=research-tls13`으로 구별합니다.

연결의 `scenario_completed`는 순수 핸드셰이크에도 적용되는 정상 완료이고 `application_verified`는 실제 응용 데이터가 있을 때만 참입니다. 측정 종료는 `end_sequence`가 가리키는 사건입니다.

사건에는 `trace_operation`, `message_id`, `message_type`, `batch_id`가 추가됩니다. 실제 내부 구간은 `INTERNAL_BEGIN/END`, 버퍼 수용은 `OUTPUT_ACCEPTED`, 소켓 제출은 성공 `IO_SEND_RETURN`입니다. 모듈·TCP 연결·accept·페이로드·응용·flush 사건의 뜻과 보고서 가용성은 [프로토타입](../design/prototype.md)을 따릅니다. 추적 미지원·꺼짐을 실제 0으로 기록하지 않습니다.

netem의 `packets.pcap`과 메타데이터는 TLS JSONL schema와 독립된 원본 관측입니다. 기존 packet JSON schema 1의 필드를 유지하면서 원본 offset, 헤더 크기·옵션·시계 짝을 추가했습니다. [TCP 분석](tcp-analysis.md)의 관측 한계를 따릅니다.

## 개정 3의 선택적 관측 확장

기존 필드의 뜻을 바꾸지 않고 `config.tx_timestamps`, `config.cpu_profile`을 추가했습니다. 두 기능은 명시적으로 요청할 때 켜집니다. 전자는 추적 모드의 커널 송신 관측, 후자는 외부 CPU 표본 실행 표지입니다. CPU 표본 수집 자체와 `perf.data`는 별도 산출물입니다. CPU 표지가 있는 쌍의 시간은 `diagnostic_only`이며 일반 시간 자동 비교에서 제외합니다.

연결 `socket`에는 `kernel_tx_timestamps`, `kernel_tx_timestamp_error`, `kernel_tx_drain_error`가 있습니다. 실제 SO_TIMESTAMPING 설정 여부와 설정·error queue 수집 errno입니다. 요청했지만 설정하지 못한 상태, 설정 뒤 필요한 사건이 없는 상태, 기능을 요청하지 않은 상태를 보고서에서 구별합니다.

`KERNEL_TX_SCHED/SND/ACK`는 기존 예약 사건 종류를 사용합니다. `raw_timestamp_ns`는 커널 CLOCK_REALTIME, `monotonic_ns`는 수집 시점의 스냅샷입니다. `timestamp_id`는 송신 요청 마지막 바이트의 0 기반 번호이고 `stream_end=id+1`이며 `stream_begin`으로 정확한 범위를 표현하지 않습니다. `timestamp_coverage_exact=false`를 유지합니다. ACK는 누적 prefix이며 SACK·세그먼트·물리 NIC 시각을 뜻하지 않습니다. [관측 위치와 정리 구간](tcp-analysis.md)을 따릅니다.

`tcp_start/tcp_end`의 `snd_cwnd`, `snd_ssthresh`는 TCP_INFO가 해당 멤버까지 돌려준 경우만 값이 있습니다. 길이 부족은 null이며 0으로 대체하지 않습니다. 초기 혼잡 윈도와 임계값은 세그먼트 단위입니다.

`trace_operation`의 기존 0~5 이름·값은 유지합니다. 추가 이름은 `kem_keygen`, `kem_encapsulate`, `kem_decapsulate`, `kem_polynomial_keygen`, `kem_polynomial_encapsulate`, `kem_polynomial_decapsulate`이며 숫자는 순서대로 6~11입니다. 이 확장 사건은 논리 호출 ID를 사용하고 TLS 메시지별 비용으로 분배하지 않습니다. KEM API의 `message_type=0`, 다항식 사건의 `message_type=1/2`는 실제 C/AVX2 분기를 뜻합니다. [중첩 범위와 검증](../experiments/mlkem-comparison.md)을 따릅니다.

netem 프로필 schema 3의 `rate_bps`, `initial_cwnd`는 TLS JSONL schema와 독립적입니다. perf 표본은 별도 `turtle-cpu-profile` schema 1 요약과 원본 바이너리 파일로 보존합니다.

## 커널 손실 관측의 별도 형식

네트워크 프로필 schema 3은 `kernel_events`와 `targeted_drop.tls_c2s/tls_s2c`를 추가합니다. target은 TLS 스트림의 0부터 시작하는 바이트 위치이고 null은 해당 방향의 지정 손실을 요청하지 않았다는 뜻입니다. 실행 권한 종류와 실제 적용한 네트워크 조건도 비교 식별에 포함합니다. TLS 원자료 schema 3와는 독립된 버전입니다.

`kernel-events.json`은 별도 schema 1입니다. 커널·BTF·BPF 오브젝트 출처, 시계 교정 짝, 연결별 최초 데이터 순번, 요청한 target과 실제 제거 여부, 커널 사건과 수집 실패·정리 상태를 남깁니다. `targeted_drop`, `qdisc_drop`, `tcp_retransmit_skb`를 구별하며 사건에는 원본 TCP 순번과 가능한 경우의 TLS 스트림 범위가 있습니다. 최초 순번을 관측하지 못한 null과 유효한 순번 0은 다릅니다. `targeted_loss_complete`는 요청 위치에 실제로 도달해 제거했는지 나타내며 TLS 정상 완료와 별도로 판정합니다.

TCP 분석 schema 2는 연결·레코드·메시지의 커널 사건 인덱스와 실제 재전송·제거 수를 추가합니다. 미수집은 null이며 관측한 사건 수 0으로 대체하지 않습니다. 요청한 필수 커널 자료가 없거나 버퍼 누락·정리 오류·지정 손실 미실현이 있으면 자동 비교에서 제외합니다. 구체적인 버퍼·시계·패킷 범위는 [TCP 분석](tcp-analysis.md)을 따릅니다.
