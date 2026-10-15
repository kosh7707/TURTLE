# 어댑터 작성 안내

## 어디서 시작하는가

계약은 `include/turtle/adapter.hpp` 하나입니다. `implementations/mock/`은 계약과 비차단 상태 진행의 예제이고, 실제 TLS 예제는 `implementations/openssl/`, `wolfssl/`, `mbedtls/`에 있습니다. mock은 TLS 구현이 아니므로 성능 비교 대상으로 쓰지 않습니다.

새 `implementations/<이름>/`에서 공유 모듈을 만들고 `turtle_adapter_v2()`를 내보냅니다. 이 함수는 소유 객체가 아닌 함수표를 값으로 돌려줍니다. `ImplementationApi::version`은 `adapter_api_version`과 같은 2여야 합니다. 초기화는 `setup`에서 수행합니다. 코어에 라이브러리 이름별 분기를 추가할 필요는 없습니다. 빌드된 `<이름>.so`를 모듈 폴더에 넣고 `--client` 또는 `--server`로 선택합니다.

이 계약은 **C++20 ABI**입니다. `extern "C"`는 진입점의 이름을 고정할 뿐, 반환하는 C++ 구조체를 순수 C ABI로 바꾸지 않습니다. C TLS 라이브러리도 얇은 C++ 어댑터로 연결하며, 프레임워크와 호환되는 컴파일러·표준 라이브러리로 함께 빌드합니다. ABI를 바꿀 때는 버전도 바꿉니다.

### ABI 2 전환

`Declaration`에 수신 선행 정책 필드가 추가되어 C++ 구조체 배치가 바뀌었습니다. 로더는 `turtle_adapter_v2` 진입점만 찾으며 v1 전용 모듈을 `declaration`이나 `setup` 호출 전에 거절합니다. 이때 오류는 `adapter ABI v2 entry turtle_adapter_v2 is missing`으로 진입점 불일치를 밝힙니다. v1 함수표를 v2로 해석하는 호환 계층은 없습니다. 기존 `.so`는 코어 실행 파일과 같은 헤더·컴파일러·표준 라이브러리로 모두 다시 빌드합니다.

어댑터 ABI 2는 모듈 바이너리 호환성을 나타냅니다. 원자료 `schema` 1은 JSON 형식의 호환성, `measurement_contract_revision=2`는 측정 귀속의 의미를 나타내며 서로 다른 버전입니다.

## 함수와 소유권

| 함수 | 책임 |
|---|---|
| `setup` | 역할별 TLS 설정, 인증서, 키, 난수원을 준비합니다. 설정·서비스는 컨텍스트보다 오래 삽니다. |
| `declaration` | 실제 판·빌드 특징과 콜백·할당·키 로그·스레드·저장·수신 선행 정책을 사실대로 설명합니다. |
| `open` | 이미 연결된 TCP와 입출력 함수로 TLS 연결 객체를 만듭니다. 소켓을 닫지 않습니다. |
| `handshake_step` | 지금 진행할 수 있는 만큼 진행하고 `WantRead`, `WantWrite`, `Done`, `Failed`를 돌려줍니다. |
| `peer_verification` | 실제 인증서 검증 결과를 돌려줍니다. 서버 인증만 하는 서버는 `NotApplicable`일 수 있습니다. |
| `app_send`, `app_recv` | 암호화된 응용 데이터를 부분 처리할 수 있습니다. 성공한 바이트 수를 돌려줍니다. |
| `negotiated` | 조회 가능한 실제 협상값을 돌려줍니다. 문자열 조회는 측정 끝 뒤에 수행합니다. |
| `error` | 실패했을 때 유효한 설명 문자열을 돌려줍니다. |
| `close`, `teardown` | 자기 객체만 해제합니다. 예외를 밖으로 던지지 않습니다. |
| `save` | 다음 셋업에 전달할 구현체 정의 상태를 반환합니다. 세션 재개는 여전히 범위 밖입니다. |

구현체는 `Context`와 `Connection`에서 파생한 자기 타입을 씁니다. 프레임워크는 그 내부를 모릅니다. 같은 호출이 준비 상태를 기다렸다가 다시 들어올 수 있습니다. 재시도할 때는 라이브러리의 동일 버퍼 규칙을 지킵니다. 런타임은 `WantRead`·`WantWrite`이면 바이트 진행이 0이어야 한다고 가정합니다.

### 수신 선행 정책 선언

`Declaration::read_ahead`는 다음 TLS 레코드까지 선행 수신하는지를 나타내는 `std::optional<bool>`입니다. `false`는 현재 레코드의 머리 또는 본문에 필요한 범위를 넘어 다음 레코드를 선행 수신하지 않는다는 뜻입니다. 요청한 바이트가 한 번에 도착한다거나, 성공한 `recv`가 레코드당 항상 두 번이라는 뜻이 아닙니다. 알 수 없거나 해당하지 않으면 `null`로 두고 `read_ahead_note`에 근거와 한계를 적습니다.

현재 고정 판에서 OpenSSL은 `SSL_CTX_set_read_ahead(..., 0)`을 명시하고 `SSL_CTX_get_read_ahead`로 0을 확인합니다. wolfSSL은 호환 필드를 0으로 저장·확인하지만 실제 TLS 수신 알고리즘은 그 필드를 읽지 않고 별도로 머리·본문의 필요 잔여량만 요청합니다. Mbed TLS에는 해당 설정 함수가 없고 고정 판의 스트림 수신 경로가 필요 잔여량만 요청합니다. 세 실제 어댑터는 이 근거로 `false`를 선언합니다. TLS 레코드를 해석하지 않는 `mock`은 `null`입니다.

수신 시험은 두 조건을 구별합니다. 요청한 바이트가 모두 준비되고 콜백이 요청량 전체를 돌려주는 통제 조건에서만 레코드 머리·본문의 두 성공 반환을 확인합니다. 3바이트씩 주는 정상 분할 조건에서는 더 많은 반환을 허용하되 각 요청이 현재 머리·본문의 잔여량을 넘거나 다음 레코드로 넘어가지 않는지 확인합니다. 실제 TCP 시험에서는 성공 반환 횟수를 통과 조건으로 고정하지 않습니다.

## 컨텍스트 저장·복원 예제

`mock`은 완료한 모의 핸드셰이크 수를 8바이트 리틀 엔디언 정수로 저장합니다. 다음 예제는
TLS나 성능 시험이 아니라 공개 계약의 저장·복원 동작을 확인하는 개발용 실행입니다.

```sh
./build/turtle run --client mock --server mock --samples 2 --output results/context-cold
./build/turtle run --client mock --server mock --samples 2 \
  --context results/context-cold/sample-000001 --output results/context-restored
```

준비 연결이 없는 위 예제에서 차가운 실행의 각 역할 출력은 1이고, 복원 실행의 두 표본은
모두 같은 입력 1에서 시작해 2를 저장합니다. 두 번째 표본이 3으로 누적되지 않습니다.
클라이언트와 서버 입력은 별도 파일이며 크기와 내용 지문도 각각 기록합니다. 세 실제 TLS
어댑터는 여전히 비어 있지 않은 저장본을 지원하지 않으며 TLS 세션 재개도 하지 않습니다.

## 준비와 계측

첫 TLS 메시지부터 모두 구현체가 만듭니다. 송수신 콜백을 지원하면 `Io.send/recv`를 연결합니다. 소켓은 실제 TCP이며 프레임워크가 비차단으로 설정합니다. 네이티브 소켓 방식은 라이브러리 경계만 보이므로 같은 송수신 수준의 결과라고 주장하면 안 됩니다.

`measurement.channel_observer`는 framework Channel의 관측 함수 선택이며 어댑터 capability나 ABI가 아닙니다. false에서도 어댑터는 같은 callback `Io`로 같은 send/recv 결과와 retry 규칙을 사용해야 합니다. framework가 stream·I/O 관측만 생략하며 keylog/plaintext host service와 TLS 호출 계약은 유지합니다. 새 어댑터는 observer 유무에 따라 프로토콜 결과나 전달 바이트를 바꾸면 안 됩니다.

자원 제한 뒤에는 새 파일이나 epoll·소켓 등을 만들 수 없습니다. 특히 난수원·인증서·공급자 모듈을 늦게 여는 라이브러리는 준비 단계나 해당 라이브러리의 공식 빌드 옵션에서 해결해야 합니다. 제한을 조용히 해제하지 않습니다.

메모리 모드의 호스트 할당 함수는 요청 바이트를 셉니다. 모든 해당 메모리는 계측기가 살아 있는 동안 해제합니다. 라이브러리 할당만 셌는지, 어댑터 자체 객체도 셌는지, 빠진 메모리가 있는지를 `memory_note`에 밝힙니다. 현재 계측기와 기록기는 단일 TLS 스레드를 전제로 합니다.

키 로그와 평문 알림은 전달받은 메모리 저장 함수에 넣습니다. 측정 중 파일에 쓰지 않습니다. 새로운 키 스케줄로 해독이 불가능해도 원자료의 함수 경계와 바이트는 남길 수 있습니다. 해독 실패를 TLS 실행 실패나 0바이트로 바꾸지 않습니다.

## 프로필과 지원 범위

공통 프로필의 모든 항목을 확인합니다. 무시한 옵션을 지원한다고 선언하지 않습니다. 조회하지 못한 협상값은 빈 값으로 남기고, 고정 허용 목록에서 추론한 값은 설명에 그 차이를 밝힙니다. 프로필의 `technique`는 현재 실험 설명용 메타데이터이며 임의 설정을 어댑터에 전달하는 별도 구성 API는 아닙니다. 추가 기법별 설정이 필요하면 공개 계약을 최소한으로 확장하고 버전·테스트·원자료도 함께 갱신합니다.

새 어댑터는 먼저 단독 실제 TCP 핑퐁을 확인하고, 이어서 프레임워크의 기본 자원 제한·새 프로세스·원자료·해독 경로로 시험합니다. 단독 시험 통과만으로 전체 실행의 성공을 주장하지 않습니다.

## 수정하지 않은 OpenSSL CLI와 상호운용 시험

`turtle_adapter_cli_endpoint`는 `include/turtle/adapter.hpp`의 공개 API만 사용해 어댑터 한 역할을 구동합니다. 생산 director나 어댑터 내부 헤더를 사용하지 않습니다. 통합 시험은 이 구동기를 수정하지 않은 `/usr/bin/openssl` 3.0.13의 `s_client` 또는 `s_server`와 실제 loopback TCP로 연결합니다.

```sh
ctest --test-dir build-tests -N -R '^openssl_cli_'
ctest --test-dir build-tests --output-on-failure \
  -R '^openssl_cli_' --repeat until-fail:20 -j 4
```

활성 OpenSSL·wolfSSL·Mbed TLS 각각에 대해 TURTLE client/server와 서버 인증/상호 인증을 조합하므로 현재 전체는 12조건입니다. 모든 조건은 callback I/O, TLS 1.3, `TLS_AES_128_GCM_SHA256`, P-256 요청, 실제 인증서 검증과 양방향 응용 바이트를 확인합니다. 양 프로세스가 exit 0으로 끝나고 wait/reap됐는지도 별도로 검사합니다. CLI argv·version·help, stdout/stderr, 어댑터 결과와 cleanup 상태는 조건별 JSON에 남깁니다.

협상 필드에는 값과 함께 `observed`, `inferred`, `unobserved` 출처를 기록합니다. OpenSSL 어댑터는 group·resumption·HelloRetryRequest를 동적으로 관측하지만 signature는 관측하지 못합니다. wolfSSL은 group·signature·resumption을 관측하고 HelloRetryRequest를 단일 허용 group에서 추론합니다. Mbed TLS의 group·signature·resumption·HelloRetryRequest는 고정 configuration에 따른 추론입니다. 추론값을 runtime 관측이라고 바꾸지 않습니다.

현재 adapter v2에는 TLS `close_notify` 함수가 없습니다. 응용 교환 뒤 객체와 소켓을 닫고 CLI에는 `-ignore_unexpected_eof`를 사용합니다. 따라서 이 시험은 정상 shutdown alert의 완전성을 검증하지 않습니다. 단독 상호운용 시험은 callback 정상 경로의 기능 증거이며 native 경로와의 동등성, director 계측, 패킷 관측이나 성능 결과를 대신하지 않습니다.
