# 기존 TLS 앱에 SDK 연결

앱의 빌드를 유지하고 **내 실행 파일 한쪽**을 계측하는 경로입니다. TLS 원본으로 양쪽 역할을 빌드하려면 [기본 제출 안내](../README.md#첫-실행)를 사용하세요.

## 설치와 연결 확인

[기본 빌드 도구](../README.md#첫-실행) 외에, 이 예시는 참조 상대역을 빌드할 OpenSSL 3.5 이상 개발 패키지와 `openssl` 명령이 필요합니다. 자기 앱을 양쪽에 쓴다면 참조 상대역 옵션은 빼세요.

```sh
work=$(mktemp -d)
cmake -S . -B "$work/build" -DCMAKE_BUILD_TYPE=Release -DTURTLE_BUILD_REFERENCE=ON &&
cmake --build "$work/build" --parallel 2 &&
cmake --install "$work/build" --prefix "$work/sdk"
```

저장소 루트에서 [S0 프로필](examples/openssl-client-s0.json)로 일반 `openssl s_client`를 실행합니다. 인증서와 호스트 이름을 검증하는 실제 TLS 1.3 연결이지만, **일반 CLI는 SDK 계측을 하지 않으므로 성능 표본은 0개**입니다.

```sh
turtle="$work/sdk/bin/turtle"
profile=docs/examples/openssl-client-s0.json
"$turtle" check "$profile" &&
"$turtle" run "$profile" "$work/s0" &&
cat "$work/s0/attempt-1/client.stderr"
```

`check`는 구성만 검사합니다. 실행 뒤 클라이언트 로그의 `Protocol version: TLSv1.3`과 `Verification: OK`를 확인하세요. `task success 0/1`은 런처가 이 앱의 시나리오 완료를 **관측값으로** 검증하지 못했다는 뜻입니다. 셸 종료 코드만으로 계측 성공을 판정하지 마세요.

## 내 앱을 계측

앱의 CMake에서 `find_package(TURTLE CONFIG REQUIRED)`와 `target_link_libraries(my_app PRIVATE turtle::endpoint)`를 추가하고, **앱**을 구성할 때 `-DCMAKE_PREFIX_PATH="$work/sdk"`를 넘깁니다. TCP 연결과 TLS 세션·인증을 준비한 뒤 첫 TLS 호출 **대신** [endpoint API](../src/include/turtle/endpoint.h)를 호출하세요.

```c
#include <turtle/endpoint.h>

const turtle_endpoint endpoint = {session, handshake_until, write_plain, read_plain};
turtle_result result = turtle_run_endpoint(&endpoint);
```

- 소켓·세션·인증은 앱이 관리합니다. 콜백은 native 재시도를 처리하고 실제 송수신 바이트 수를 돌려줍니다. EOF, 미지원, 오류를 각각 `TURTLE_CLOSED`, `TURTLE_UNSUPPORTED`, `TURTLE_ERROR`로 구분하세요. S2/S4 서버는 client Finished를 기다리지 않고 쓸 수 없다면 미지원으로 반환합니다.
- SDK는 준비 신호, 시작 대기, 동작 순서, 테스트 평문 검증을 처리합니다. 첫 TLS 호출 전에 연결을 SDK에 넘기고, 같은 연결에서 시작 대기를 중복 호출하지 마세요. 표준 입출력은 앱 데이터 교환용입니다. 앱 진단은 stderr에 쓰세요.
- 계측 대상에서는 `turtle_run_endpoint()` 호출 **전**(READY 전)에 [양방향 암호문 훅](../src/include/turtle/observe.h)을 켜고, 반환 **후**에 끄세요. `turtle_observe_coverage`로 범위를 열고 닫으며, `turtle_observe_io`로 각 호출의 시작·끝과 실제 반환값을 기록합니다. [참조 구현](../tools/reference/main.cpp)이 이 순서를 보여줍니다. 장기 실행 앱이나 `_exit()`를 쓰는 앱은 관측 종료 후 측정 구간 밖에서 동시 콜백 없이 `turtle_observe_flush()`를 호출하세요.
- 성능 표본이 적격이라는 것만으로 TLS 협상·인증이 입증되지는 않습니다. 이 증거까지 필수로 보려면 앱에서 `turtle_observe_identity`, `turtle_observe_fact`와 `auth_accepted` 사건을 보고하고 프로필에 `"required_metrics": ["authentication", "profile"]`을 넣으세요.

프로필을 복사해 `target.role`과 `target.argv`를 앱에 맞추세요. 각 인자는 배열의 한 항목입니다. 실행 파일에 경로가 있으면 프로필 기준, 이름만 있으면 `PATH` 기준입니다. 런처는 `{host}`, `{port}`, `{ca}`, `{cert}`, `{key}`, `{peer_name}`을 치환합니다. 서버는 받은 주소·포트에서 직접 listen하고, 인증서·키·검증 이름은 인자 또는 `TURTLE_CA`·`TURTLE_CERT`·`TURTLE_KEY`·`TURTLE_PEER_NAME`으로 받으세요. 기본 시험 인증은 `openssl` 명령으로 발급한 임시 인증서를 사용합니다.

`peer.argv`를 지정하면 참조 상대역 대신 내 상대역을 실행합니다. 시간 비교에 쓸 표본은 양쪽이 준비된 후 시작해야 하므로, 자체 상대역에도 SDK 시작 절차를 연결하세요. `scenario`는 S0–S4, `auth`는 `server` 또는 `mtls`입니다. `warmups`와 `repetitions`는 새 연결 수, `application`의 `request`·`greeting`·`response`는 앱 페이로드입니다. 네트워크는 기본 `loopback`입니다. 왕복 지연을 20 ms 추가하려면 프로필에 `"network": "netem", "netem": {"additional_rtt_ms": 20}`을 넣으세요. 이 옵션은 네트워크 네임스페이스 생성·설정 권한과 `ip`, `tc`, `ethtool`, `sysctl`이 필요합니다. [시나리오별 측정 구간](submission.md#시나리오와-측정-구간)은 제출 경로와 같습니다. `turtle run PROFILE NEW_OUTPUT`에는 아직 없는 출력 경로를 넘깁니다.

콘솔의 완료·적격 표본 수부터 보고, `Details:`가 가리키는 `analysis.json`에서 시도별 제외 사유를 확인하세요. 벽시계와 PMU 가용성은 별개입니다. 미관측은 0이 아닙니다. `attempt-N/{client,server}.stderr`는 각 역할의 실행 로그입니다. `turtle analyze RUN`은 TLS를 다시 실행하지 않고 RUN의 분석 결과를 갱신합니다.
