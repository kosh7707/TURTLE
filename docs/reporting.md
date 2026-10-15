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

## 서버의 ClientHello→Finished 구간

`server_client_hello_to_finished_send`는 서버가 ClientHello를 받기 시작한 반환에서
자기 Finished를 보내기 끝낸 반환까지의 추가 구간입니다. 정의 문자열은
`server_client_hello_receive_return_to_server_finished_send_return`입니다.

- 시작은 ClientHello가 든 TLS 레코드 외피의 첫 바이트를 포함해 성공한 `IO_RECV_RETURN`입니다. 네트워크 도착 시각이 아니며, 이 반환이 레코드 본문 전체를 받았다는 뜻도 아닙니다.
- 끝은 서버 Finished가 든 레코드 외피의 마지막 바이트까지 실제로 보낸 성공한 `IO_SEND_RETURN`입니다. 부분 송신이면 마지막 바이트까지 모두 보낸 반환을 기다립니다. 하나의 반환에 여러 레코드가 묶이면 그 실제 반환 경계를 씁니다.

연결 결과에는 경과 시간과 스레드 CPU 시간, 사용 가능할 때 사이클, `start_event_sequence`, `end_event_sequence`, `client_hello_bundled`, `finished_bundled`를 남깁니다. `mapping`은 `record_envelope_overlap`입니다. 스레드 CPU 스냅샷이 없거나 역전되어도 경과 시간을 만들 수 있으면 유지하고, CPU 값만 `null`과 `thread_cpu_reason`으로 남깁니다. 그룹 지표 이름은 다음과 같습니다.

- `server_client_hello_to_finished_send_elapsed_ns`
- `server_client_hello_to_finished_send_thread_cpu_ns`
- `server_client_hello_to_finished_send_cycles`

이 구간은 서버의 호환용 ChangeCipherSpec과 서버 인증서·CertificateVerify·Finished 생성을 경계 안에서 실제 처리한 배치대로 포함합니다. 응용 핑퐁과 Finished 뒤의 NewSessionTicket은 포함하지 않습니다. TLS 1.3에서 서버 Finished 송신은 클라이언트 Finished 검증보다 앞입니다. 상호 인증에서도 클라이언트 Certificate·CertificateVerify 수신과 검증보다 앞이므로, 이 구간을 서버의 전체 상대 인증 완료 시간이라고 부르지 않습니다.

I/O 사건이나 완전한 해독 레코드 대응이 없으면 값을 만들지 않고 `available=false`와 이유를 남깁니다. 이 구간은 기존 서버 주 구간을 대체하지 않습니다.

## 레코드 경계와 연산 구간의 귀속

각 연결의 `record_computation_attribution`은 주 구간 안의 `computation` 구간을 다시 측정하지 않고 시작과 끝에 레코드 근거를 붙입니다. `scope` 값은 `primary_window_computation_segments`입니다.

- `after_receive`는 TLS 레코드 외피의 마지막 바이트까지 실제로 받은 성공 `IO_RECV_RETURN` 뒤에 시작한 연산 구간에 붙습니다. 레코드 머리만 받은 반환에는 붙이지 않습니다.
- `before_send`는 같은 연결·호출의 `IO_SEND_ENTER`와 `IO_SEND_RETURN`을 순서대로 짝지은 뒤, 성공 반환이 실제로 보낸 바이트 범위의 레코드만 전송 앞 연산 구간에 붙습니다. 요청한 길이나 성공 0바이트를 완료 근거로 쓰지 않습니다.
- 연산 구간이 `CALL_BEGIN`에서 시작하면 `call_begin`, `CALL_END`에서 끝나면 `call_end`를 남깁니다. 레코드 대응이 없거나 양끝 중 하나에 귀속이 없는 연산 구간도 삭제하지 않습니다.

각 `segments` 항목은 `segment_index`, `begin_event_sequence`, `end_event_sequence`, `elapsed_ns`, `thread_cpu_ns`, `thread_cpu_reason`, `start`, `end`를 가집니다. `start`와 `end`는 각각 `null`이거나 `kind`, `boundary_event_sequence`, `io_return_event_sequence`, `record_indices`, `names`, `bundled`, `mapping`을 담은 객체입니다. 레코드 귀속의 `mapping`은 `record_envelope`, 호출 경계의 `mapping`은 `boundary_event`입니다. 호출 경계의 I/O 반환 순번은 `null`이고 레코드·이름 목록은 비어 있습니다. 한 연산 구간의 양끝에 모두 귀속이 있어도 구간과 시간은 한 번만 저장합니다.

해독기의 메시지 이름은 해당 레코드를 사용한 평문 메시지입니다. `names`는 이름 문자열이 아닌 메시지 인스턴스를 기준으로 만듭니다. 예를 들어 NewSessionTicket 두 개가 같은 경계에 묶이면 `names`에 같은 이름을 두 번 남기고 `bundled=true`입니다. 문자열을 중복 제거하지 않습니다.

하나의 메시지가 여러 레코드에 걸치면 먼저 받은 레코드의 외피가 완성된 시점과 메시지 전체가 완성된 시점은 다릅니다. 이 한 메시지만 여러 레코드에 걸친 사실은 묶임이 아닙니다. `bundled`는 현재 I/O 경계의 `record_indices`에서 같이 선택된 메시지 인스턴스만으로 판정합니다. 다른 레코드에서만 다른 메시지와 공유한 상태를 현재 경계의 묶임으로 전파하지 않습니다. 반대로 한 레코드에 여러 메시지가 들면 인스턴스별 이름을 모두 남기고 `bundled=true`로 표시합니다. 하나의 암호화 레코드를 여러 번에 나눠 보내면 같은 레코드·메시지 이름이 여러 `before_send`에 나타날 수 있습니다. 이때 `names`는 해독한 레코드 외피가 겹친 후보이며, 그 반환 바이트에 각 메시지 전체가 독립적으로 들었다는 뜻이 아닙니다. 어느 경우에도 구간 시간을 이름 수로 나누거나 같은 이름으로 다시 합산하지 않습니다.

이 보기는 라이브러리가 언제 작업을 배치했는지를 보는 구조 진단입니다. 특정 메시지의 내재적 비용이나 순수한 라이브러리 연산 시간이 아닙니다. 측정 계약 개정값 1은 I/O 반환 스냅샷 뒤에 스트림을 복사했으므로 그 비용이 후속 연산 구간에 들 수 있었습니다. 개정값 2는 스트림 복사와 반환·`KernelRx` 고정 공간 준비를 스냅샷 전 I/O로 옮겼지만, 복합 계측 읽기와 스냅샷 뒤 공간 대입·복귀 비용은 남습니다. 개정값 1의 귀속을 2로 소급 보정하지 않습니다. 특히 묶인 이름의 시간을 메시지별로 비교하지 않습니다. 비교가 필요하면 개별 이름이 아니라 `client_hello_to_finished_send`나 `server_client_hello_to_finished_send`같이 같은 이름·같은 경계로 정의한 전체 구간의 합계를 씁니다. `record_computation_attribution`은 그룹 통계나 자동 비교를 만들지 않습니다.

I/O가 관측되지 않았으면 원자료의 이유, 예를 들어 `channel_observer_disabled`나 `native_socket_io_not_observed`를 그대로 남기고 `segments=null`입니다. 이유가 없는 구 자료는 `io_events_not_observed`로 남깁니다. 해독 파일이 없으면 `decoded_sidecar_absent`, 손상·불완전하면 `decoded_sidecar_<기존 이유>`, 레코드 대응을 만들 수 없으면 `decoded_record_mapping_unavailable`입니다. 경과 시간이 있어도 CPU 스냅샷이 없거나 역전되면 해당 `thread_cpu_ns`만 `null`이고 이유를 따로 남깁니다.

## 기능 유효성과 지표 가용성

`connections[*].valid`는 인증과 응용 교환을 포함한 기능 결과입니다. `primary_window`와
`io_breakdown`은 그 연결에서 특정 측정 구간·분해를 관측할 수 있는지 따로 설명합니다. 한쪽을
다른 쪽으로 대신하지 않습니다.

- 콜백 클라이언트와 서버는 기존 주 구간과 I/O 분해를 계산합니다.
- 라이브러리 직접 소켓을 쓰는 클라이언트는 첫 핸드셰이크 호출부터 마지막 응용 수신 완료까지의 `elapsed_ns`와 `thread_cpu_ns`를 보존하지만 `computation_ns`, `io_ns`, `wait_ns`, `gap_ns`는 `null`입니다.
- 라이브러리 직접 소켓을 쓰는 서버는 첫 성공 프레임워크 수신을 볼 수 없으므로 주 구간 자체를 사용할 수 없으며 경과·CPU를 만들지 않습니다.

라이브러리 직접 소켓 그룹은 관측 수준이 `library-only`이고 스트림·I/O를 관측할 수 없으므로 기존 자동 성능 비교에서 항상 제외합니다. 해당 클라이언트에 호출 경과가 있다는 이유로 콜백 경로와 자동 비교하지 않으며, 해당 서버의 없는 값을 0이나 순수 연산으로 채우지 않습니다. 주 `elapsed_ns`가 없는 그룹은 묶음과 비교 후보 계산에서도 제외합니다.

### 양 역할·양 모드의 공통 호출 경계

`handshake_call_begin_to_application_complete`는 관측자 켬/끔과 라이브러리 직접 소켓 경로를 포함해 CALL 사건이
남은 실행에 공통으로 계산할 수 있는 별도 경계입니다. 첫 `handshake` `CALL_BEGIN`에서 역할별
전체 응용 요청을 완료한 마지막 성공 `CALL_END`까지입니다. 클라이언트 끝은 `app_recv`, 서버 끝은 `app_send`입니다. 여러 부분 호출의 `transferred`를 요청량까지 합산하며 재시도나 첫 부분
성공을 완료 경계로 쓰지 않습니다. 준비 연결과 다른 연결 사건도 섞지 않습니다.

표본에는 정의, 가용 여부와 이유, 시작·끝 사건 순번, `elapsed_ns`,
`thread_cpu_ns`와 `thread_cpu_reason`을 남깁니다. 경과 시간이 유효해도 CPU 스냅샷 누락·역행이면
CPU만 `null`일 수 있습니다. 공통 경계가 유효하더라도 기존 서버 주 구간을 만들어 내지 않으며,
primary `elapsed_ns`가 없는 그룹은 기존 자동 비교·묶음에 계속 부적격입니다. M6에서 “라이브러리 직접 소켓을 쓰는 서버의 주 경과·CPU가 없다”는 사실은 유지되지만 이 이름 있는 공통 경과·CPU는 따로
존재할 수 있습니다.

그룹 지표 이름은 `handshake_call_begin_to_application_complete_elapsed_ns`와
`handshake_call_begin_to_application_complete_thread_cpu_ns`입니다. `run_controls.channel_observer`
도 조건 식별값에 들어가고 과거 필드 부재는 `true`입니다. TLS 표본, 상위 프로세스 시도 또는 필요한
네트워크 무결성이 실패하면 원자료에 계산 가능한 공통 경계가 있더라도 그룹 분포에는 넣지
않습니다.

관측자 켬/끔 진단은 같은 역할끼리 원자료의 공통 경계 분포와 단순 산술 차이를 남깁니다. 차이의
부호·크기·0 여부나 통계적 유의성을 합격 기준으로 쓰지 않습니다. 끔 상태에서도 호출·대기,
키 로그·평문 알림, 성능 카운터·시계 읽기가 남으므로 이 차이는 관측자 함수만의 순수 비용이나 완전한
계측 보정값이 아닙니다. 전체 계측 비용의 수학적 상한이나 하한도 아니며, 서버의 계측 없는
외부 기준선을 대신하지 않습니다.

## 자동 비교 후보

자동 비교는 같은 역할을 측정한 두 그룹 가운데 실행 조건이 같은 경우만 후보로 냅니다.
클라이언트를 측정할 때는 클라이언트 어댑터 이름과 그 라이브러리 이름, 버전, 빌드 옵션만
달라도 됩니다. 서버 어댑터는 같아야 합니다. 서버를 측정할 때는 반대로 서버 쪽 식별 정보만
달라도 되고 클라이언트 어댑터는 같아야 합니다.

프로필, 실행 제어값, 컨텍스트를 불러왔는지 여부, CPU 고정 결과, 측정 모드, 관측 수준,
환경은 같아야 합니다. 이 규칙은 측정하는 쪽의 구현을 바꾸면서 상대 엔드포인트를 고정한
후보를 찾기 위한 것입니다.

자동 비교하려는 두 그룹은 자기 역할끼리, 상대 역할끼리 측정 경계 계약이 같아야 합니다.
하나의 연결 안에서 클라이언트와 서버 개정값을 서로 같게 만드는 규칙을 뜻하지 않습니다. 일반 보고서는 자기 역할의 값을
`dimensions.measurement_contract_revision`, 상대 역할의 값을
`dimensions.peer_measurement_contract_revision`에 남깁니다. 조회 보고서는
`condition_identity.client_endpoint.measurement_contract_revision`과
`condition_identity.server_endpoint.measurement_contract_revision`에 각각 남깁니다. 같은 명시적 개정값은
다른 조건이 맞으면 기존 자동 비교 후보를 만들 수 있지만, 서로 다른 개정값은 하나의
계약으로 정규화하지 않습니다.

예전 원자료처럼 개정 필드가 없거나 값이 양의 정수가 아니면 해당 차원은 JSON `null`인 알 수 없음입니다.
자기 역할이 알 수 없으면 `measurement_contract_revision_unknown`, 상대 역할이 알 수 없으면
`peer_measurement_contract_revision_unknown`을 `comparison_exclusion_reasons`에 남기고 자동 비교에서만
제외합니다. 이 판정은 지표 수용 조건이 아니므로 기존 성공 연결, 표본 수, 지표와 분포는
계속 보고합니다. 조회 보고서에서는 클라이언트 계약을 알 수 없을 때
`missing_identity:client_measurement_contract_revision_unknown`, 서버 계약을 알 수 없을 때
`missing_identity:server_measurement_contract_revision_unknown`을 남깁니다. 이 경우
`missing_identity:endpoint_identity_incomplete`도 함께 남지만 설명용 분포와 분모는 삭제하지
않습니다.

성능 카운터 조건은 요청·상태·실제 범위를 함께 사용합니다. 일반 보고서의 새 명시 원자료는 `groups[].dimensions.run_controls.perf_scope`, `perf_support.{perf_requested_scope,perf_status,perf_effective_scope}`를 남깁니다. 상대 엔드포인트는 `peer_run_controls.{perf,perf_scope}`와 `peer_perf_support`의 같은 세 필드를 사용합니다. `disabled`은 `perf=false`와 실제 범위 `null`, `unsupported`는 `perf=true`와 실제 범위 `null`일 때 완전한 조건입니다. `available`은 `perf=true`이고 실제 범위가 요청 범위와 같아야 합니다.

조회 보고서는 `joined_rows[].condition_identity.client_endpoint`와 `server_endpoint`의 `measurement_controls.{perf,perf_scope}` 및 `support.{perf_requested_scope,perf_status,perf_effective_scope}`에 같은 조건을 남깁니다. 조건 그룹도 이 엔드포인트 식별값을 그대로 가집니다. 실패 단계, errno, `perf_note`는 해당 실행의 진단이므로 일반·조회 조건 키에 넣지 않습니다. 따라서 요청·상태·실제 범위가 같고 다른 조건도 같은 자료는 진단 문구나 errno가 다르다는 이유로 별도 그룹이 되지 않습니다.

필드 **부재**와 명시적 JSON `null`은 다릅니다. 원자료에 `perf_scope`나 요청·상태·실제 범위 중 일부가 있지만 `capabilities.perf_effective_scope`만 없으면, 일반 보고서의 해당 `perf_support` 또는 `peer_perf_support`와 조회 보고서의 해당 엔드포인트 `support`에서 `perf_effective_scope` 키 자체를 생략합니다. 원자료에 키가 있고 값이 `null`이면 보고서에도 `"perf_effective_scope": null`을 그대로 남깁니다. 새 존재 여부 표식이나 형식 개정값을 만들지 않습니다.

안정 필드 전체가 없는 완전한 구 자료는 일반 보고서에서 `perf_support`를 만들지 않고, 조회 보고서에서는 기존 세 필드의 `null` 표현을 유지합니다. 일부만 누락된 자료는 일반 보고서의 `perf_condition_unknown` 또는 `peer_perf_condition_unknown`, 조회 보고서의 `missing_identity:client_perf_condition_unknown` 또는 `missing_identity:server_perf_condition_unknown`과 `missing_identity:endpoint_identity_incomplete`를 남깁니다. 이 경우 자동 비교만 제외하며 경과 시간·스레드 CPU와 조회 TLS·CA CPU의 표본·분포는 계속 보존합니다. 알려진 `disabled`·`unsupported`의 명시적 실제 범위 `null`은 알 수 없음으로 취급하지 않습니다.

상대 엔드포인트가 고정되었는지는 같은 표본 폴더의 반대 역할 원자료 머리글로 확인합니다.
두 머리글의 표본 번호, 묶음 번호, 프로필이 맞아야 합니다. 비교 조건에는 양쪽에 실제로
고정된 CPU 번호와 상대 어댑터의 라이브러리 이름, 버전, 빌드 옵션, 유효 여부, 계측 지원
정보가 들어갑니다. 반대 역할 파일이 없거나 머리글을 확인하지 못한 단일 역할 결과도
요약에는 남지만 자동 비교 후보에서는 제외합니다. `director.txt`가 표본을 무효라고
표시하면 그 폴더의 역할 결과도 유효한 그룹에 넣지 않습니다.

두 그룹이 포함한 묶음 번호의 집합도 완전히 같아야 합니다. 서로 다른 묶음에서 나온 두
그룹을 자동으로 비교하지 않습니다.

양쪽 엔드포인트에서 조회한 실제 소켓 설정도 비교 조건에 포함합니다. 준비 연결과 측정 연결의
실제 설정을 모두 순서대로 조건 식별값에 넣습니다. 요청 버퍼 크기가 같더라도 커널이 적용한
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

조회 원자료가 없는 일반 TLS 실행도 네트워크 인계가 있으면 요청 정책과 실제 적용 정책을 모두 안정 그룹 키에 넣습니다. 요청 식별값은 역할 원자료의 `network_handoff.net_profile`, 실제 식별값은 출처 기록에서 변동값을 제거한 토폴로지·활성 경로·qdisc 적용값 재조회·MTU·offload 조건입니다. 따라서 0ms와 20ms 또는 클라이언트와 서버 역할은 서로 다른 그룹이며, CA 경로가 없는 세 이름공간 토폴로지는 조회용 네 이름공간 토폴로지와 섞이지 않습니다.

호스트 불변, 단계 관측 완전성, 보조 프로세스·관측자 회수 같은 무결성 **결과**는 안정 그룹 키에 넣지 않습니다. 같은 요청·실제 정책에서 무결성 결과가 달라도 조건 그룹을 새로 만들지 않고, 원래 실행 수준 출처 기록·시도 부가정보와 표본의 `network_integrity`, 그룹의 최상위 `automatic_comparison_eligible`에서 부적격을 표시합니다. 부적격 표본의 측정값은 그룹 지표에 넣지 않습니다. 성공·시간 초과, 폐기와 재전송도 같은 이유로 조건 키가 아닙니다.

준비 연결과 측정 연결의 실제 소켓 설정은 모두 조건을 구성하지만, 경과 시간·스레드 CPU를 비롯한 지표에는 `warmup=false`인 측정 연결만 들어갑니다. 준비 연결을 표본 수나 지표 수에 더하지 않습니다.

### 콜백·라이브러리 직접 소켓의 외부 흐름 부가정보

M6의 외부 확인은 조회가 꺼지고 지연·손실이 0이며 추적을 켠 기존 실행기를 그대로 사용합니다. 콜백과 라이브러리 직접 소켓 경로를 각각 새 출력에서 2회 실행하고, 요청·실제 네트워크 식별값, 정확한 여섯 단계 참조, 호스트 불변과 정리 무결성을 같은 판독기로 확인합니다. M13·M14의 `verify`나 N05는 실행하지 않습니다.

`external-observation.json`은 각 방향에서 수신자 쪽 router 송신 인터페이스, 송신 방향, 기대 주소·TCP 4-tuple과 양의 페이로드를 만족하는 행만 선택해 `observed_skb_count`와 `payload_byte_sum`을 나란히 보존합니다. 시각은 커널·NIC 도착 시각이 아니라 AF_PACKET 관측자가 사용자 공간에서 읽고 해석한 시각입니다. 시나리오 표식으로 자른 창도 정확한 TLS 단계가 아니라 관측자가 읽은 시각에 근거한 근사 구간입니다. 재전송·분할 때문에 개수는 고유 TLS 레코드나 물리 패킷 수가 아니고 페이로드 합도 중복 제거된 TLS 바이트가 아닙니다. 두 경로의 수치가 같아야 한다는 조건은 없으며 전체 pcap·시스템 호출 추적·물리 전송 증거로 확대하지 않습니다.

## 인증서 조회 시나리오 보고

조회 원자료가 있으면 `turtle-report`는 기존 `summary.json`과 별도로 `lookup-summary.json`을 만듭니다. 보고서 제목과 `scenario_disclosure`는 이 실행이 **합성 조회 + 수정하지 않은 인증서 기반 TLS**이며 인증서 경량화 결과가 아님을 명시합니다.

### 분모와 상태

`attempts.jsonl`의 상위 프로세스 최종 행이 상태의 기준입니다. 자식 파일의 `valid=true`가 상위 프로세스의 `timeout`이나 `error`를 덮지 않습니다. 원장에는 다음 항등식이 유지되어야 합니다.

```text
requested = started + not_attempted
started = success + timeout + error + incomplete
```

`attempt_table`은 시도 상태와 그 시도에 속한 연결 행 참조를 담습니다. `connection_table`은 준비 연결 여부와 연결 상태를 담습니다. 여러 연결의 시간을 더해 독립 시도 시간으로 만들지 않습니다. 시간 초과의 누락값을 성공 분포에 시간 초과 길이나 0으로 넣지 않습니다. 과거 원자료에 원장이 없으면 TLS 머리글과 `director.txt` 대체 판독을 명시적으로 표시하며, 새 원장이 있을 때는 대체 판독으로 상태를 바꾸지 않습니다.

### 연결 행의 시간과 자원

`joined_rows`는 조회·CA·TLS와 네트워크 관측을 `(attempt, connection, request_id)` 및 관측 ID로 연결합니다.

- `remote_lookup_duration_ns`: 캐시 누락의 `REQUEST_BEGIN`→`RESPONSE_COMPLETE`입니다. 캐시 적중이면 해당 없음 `null`입니다.
- `usable_duration_ns`: 조회 시작→`USABLE_OBJECT`입니다. 응답 수신 뒤 바이트 대조와 캐시 삽입을 포함합니다.
- `tls_elapsed_ns`: 기존 클라이언트 TLS 경계입니다. 조회 시간이 섞이지 않습니다.
- `scenario_elapsed_ns`: 조회 시작부터 TLS 완료까지의 시나리오 경계입니다.
- `ca_process_ns`, `ca_cpu_ns`, `ca_io_ns`, `ca_wait_ns`: 모의 CA 엔드포인트의 독립 경계입니다.
- `tcp_counter_deltas`: 조회, CA, TLS 클라이언트·서버 소켓의 시작·끝 차이입니다.

CA 처리, I/O와 대기는 서로 겹치거나 포함 관계가 있을 수 있는 관측 경계입니다. `remote_lookup_duration_ns`를 RTT라고 부르거나 CA 시간과 더해 총시간을 만들지 않습니다. 보고서도 `ca_plus_rtt=never_summed` 규칙을 남깁니다.

### 손실 근거와 조건 그룹

netem 요청 손실은 조건이고, qdisc 실제 폐기는 커널 패킷 버퍼 단위 집계 결과이며, `TCP_INFO.total_retrans` 차이는 소켓의 TCP 재전송 결과입니다. 세 값은 단위와 관측 위치가 다릅니다. AF_PACKET 행도 물리 패킷이 아닙니다. TSO/GSO/GRO 요청값과 적용값 재조회를 함께 읽어야 하며, qdisc 집계를 특정 연결에 나눠 주거나 연결 수만큼 더하지 않습니다.

조건 그룹에는 합성 시나리오, 캐시 모드와 초기 상태, 객체 ID·크기, TLS 프로필, 연결 정책, 실제 CPU·소켓 준비값, 토폴로지, 방향별 qdisc 정책, MTU, offload 요청·실제값 같은 안정 조건만 넣습니다. 이름공간 PID·FD·경로, 동적 포트, qdisc handle, 시각 같은 출처 기록과 성공·시간 초과, 폐기·재전송 같은 **결과**는 그룹 키에서 뺍니다. 결과가 다르다는 이유로 같은 조건을 서로 다른 그룹으로 나누지 않습니다. 반대로 필수 조건 식별값이 없거나 실제 offload·MTU·소켓 준비값이 다르면 자동 비교에서 제외하거나 그룹을 나눕니다.

고정 netem 검증 manifest의 일곱 실행은 각 실행의 원장·네트워크 출처 기록·호스트 불변·소유 자원 정리 무결성을 통과했습니다. 최신 보고 도구는 성공한 네트워크 시도마다 셋업·시나리오·정리의 시작과 끝에 해당하는 정확히 여섯 관측 참조를 확인하고, 호스트 불변과 소유 자원 정리를 자동 비교 적격성에 반영합니다. 참조·출처 기록·원장이 누락되거나 잘못되면 보수적으로 실패합니다.

루프백 자료는 네트워크 무결성이 해당 없음이므로 측정값을 설명용 분포에 남길 수 있습니다. 그러나 격리 토폴로지·실제 적용 네트워크 식별값이 없으므로 자동 네트워크 비교 적격성은 얻지 않습니다. **설명용 지표 보존과 비교 적격성은 별도 판단입니다.**

`results/mock-ca-goal/netem-verify-final/report-final/lookup-summary.json`은 보존한 일곱 실행을 합산합니다. `requested=started=100`, `success=97`, `timeout=3`이며 시도·연결·결합 행이 각각 100개입니다. 일곱 조건은 각각 자기 분모와 조건 그룹을 유지합니다. 시간 초과 세 건은 비교 분포에 들어가지 않습니다.

194개 유효 TLS 역할 파일은 모두 해독됐습니다. 시간 초과에서 없거나 유효하지 않은 역할 파일 6개는 그대로 결측으로 남겨 성공으로 승격하지 않았습니다. `latency-diagnostics.json`의 중앙값은 경로 동작을 보는 `diagnostic_only` 값이며 어떤 통과 조건도 지연 임계값으로 판정하지 않습니다. 논문 성능 주장에도 사용하지 않습니다.
