# 내 TLS 구현체로 시나리오 실행하기

앱은 평소처럼 TCP 연결을 만들고, 클라이언트 또는 서버 역할과 TLS 정책을 설정한다. **첫 TLS 입출력 전**에 [`turtle_endpoint`](../include/turtle/endpoint.h)를 채워 `turtle_run_endpoint`를 한 번 호출한다. 앱이 소유한 연결을 잠시 빌려주는 것이므로, 반환 후 소켓과 TLS 세션 정리도 앱에서 한다. 서버만 시험할 때 개발자가 클라이언트까지 작성할 필요는 없다.

| 개발자가 연결할 곳 | 무엇을 반환하는가 |
|---|---|
| `conn` | 준비된 자기 연결을 가리키는 포인터. TURTLE은 내부를 해석하지 않는다. |
| `handshake_until(conn, goal)` | `TURTLE_LOCAL_COMPLETE`: 로컬 full handshake 성공. **S2/S4 서버만** `TURTLE_SERVER_CAN_SEND`도 지원한다. 서버 Finished를 내보낸 뒤 클라이언트 Finished를 기다리지 않고 쓸 수 있는 첫 기회에 반환한다. |
| `write_plain(conn, at, buf, len, &n)` | TLS가 실제 수락한 평문 바이트 수. `at`은 위 두 시점 중 하나다. 선송신을 요청받고 내부에서 핸드셰이크부터 끝내거나, 나중에 보낼 앱 큐에 복사한 뒤 성공으로 보고하지 않는다. |
| `read_plain(conn, buf, capacity, &n)` | **일반 평문 읽기**가 앱에 돌려준 실제 바이트 수. 버퍼가 다 찰 때까지 모으지 않는다. S2 클라이언트에서는 이 읽기가 첫 TLS 호출일 수 있으므로, 필요한 TLS 진행을 구현체의 정상 경로로 수행한다. |
| TLS와 전송 계층 사이의 송수신 훅 | 완전한 측정 표본을 얻으려면 측정 대상의 송신과 수신 모두를 준비부터 측정 끝까지 관찰한다. 실제 전송 호출의 방향·요청 길이·결과·암호문을 연결한다. 아래처럼 기존 훅을 먼저 붙이면 별도 등록 콜백은 없다. |

필요하지 않은 읽기나 쓰기 콜백은 `NULL`이어도 된다. 필요한 콜백이 없거나 진짜 선송신 경로가 없으면 `TURTLE_UNSUPPORTED`다. 읽기·쓰기는 양수 길이로 호출하고, `TURTLE_OK`일 때만 `0 < n <= 요청 길이`를 인정한다. 부분 성공은 정상이다. SDK가 바이트를 누적하므로 구현체가 메시지 길이·시나리오 번호를 알 필요가 없다. EOF는 `TURTLE_CLOSED`, 그 밖의 실패는 `TURTLE_ERROR`다. 실패를 0바이트 성공으로 바꾸지 않는다. 비동기 TLS API의 대기·재시도는 앱의 정상 경로를 사용해 이 동기식 호출 안에서 처리한다. C++ 예외를 C 호출 경계 밖으로 던지지 않는다.

## 누가 언제 호출하는가

`H`는 로컬 핸드셰이크 완료 확인, `E`는 서버 선송신 가능 시점, `W`와 `R`은 평문 쓰기와 읽기다. 각 행의 두 역할은 동시에 진행한다. 이 표를 **개발자가 코드로 작성하지 않는다**.

| 시나리오 | 클라이언트에서 SDK가 하는 일 | 서버에서 SDK가 하는 일 |
|---|---|---|
| S0 | H | H |
| S1 | H → W(요청) | H → R(요청) |
| S2 | **R(안내)부터 시작** → H 확인 | E → W(안내, E) → H |
| S3 | H → W(요청) → R(응답) | H → R(요청) → W(응답) |
| S4 | H → **W(요청)** → R(안내·응답) | E → W(안내, E) → H → R(요청) → W(응답) |

S2의 첫 끝점은 **첫 양수 평문 읽기의 반환 직후**다. 예를 들어 `helo`가 `he / lo`로 반환되면 첫 반환이 첫 평문 시각이다. 두 번째 반환으로 전체 평문이 도착하며, 전체 내용 확인은 SDK가 별도로 끝낸다. 뒤의 H는 그 호출이 성공한 시점의 확인이지, 과거의 TLS 내부 완료 시각이 아니다. 실패한 읽기나 BIO 암호문 도착으로 첫 평문 시각을 만들지 않는다. 일반 읽기 내부에서 TLS가 핸드셰이크를 진행하는 것은 허용한다. 새 S2 표본에는 이 읽기를 처음에 걸고 안내를 받은 뒤 로컬 완료를 확인한 근거가 필요하다. 앱이 별도 완료 호출을 먼저 했다면 실제 첫 평문 반환은 보존하지만 같은 S2 표본으로 세지 않는다. S4에서는 첫 안내 읽기 전에 CAD 전부를 TLS가 수락해야 한다. 첫 쓰기 시도나 일부 수락만으로는 부족하다.

S3/S4 서버 SDK는 준비 단계에서 응답(SAD₂) 바이트를 확보하지만, **로컬 핸드셰이크 완료와 요청(CAD) 전체 검증 뒤에만** TLS 쓰기를 시작한다. 감독 프로세스와의 stdout/stdin 대조는 서버의 측정 종료 뒤에 처리한다. 새 SDK의 서버 `lifecycle.ready.response_source`가 `prepared_environment`일 때만 이 경로를 확인할 수 있다. 일반 stdin/stdout 서버에는 요청 전체가 stdout에 나타난 뒤에만 응답을 공급하며, 과거 시행도 새 경로로 해석하지 않는다.

`wall_ns`는 역할별 SDK 사건 사이의 단조 시계 경과 시간이다. TLS·네트워크 대기와 그 사이의 SDK 처리도 포함하므로 순수 암호 연산 시간이나 RTT는 아니다. 하드웨어 CPU 계수는 같은 구간에서 **측정 대상 스레드**의 사용자 공간 실행만 센다(커널·하이퍼바이저 제외, 다른 스레드로 상속하지 않음).

TLS 구현체는 설정된 인증 정책대로 동작한다. 인증서 검증 결과·암호군·내용 검증·타임스탬프용 콜백은 필요 없다. SDK가 시험 평문을 비교한 결과나 H의 성공은 별도의 인증·협상 세부 증거가 아니다. 서버의 선송신 쓰기는 상대 클라이언트의 Finished 전 도달이나 인증 완료를 보장하지 않는다. 일반 벤치마크에 이를 입증하는 추가 장벽은 없다.

## 빌드와 실행

기존 빌드에 설치한 SDK 하나를 연결한다. DUT의 TLS 라이브러리를 TURTLE의 코어나 소스 트리에 넣지 않는다.

```cmake
find_package(TURTLE CONFIG REQUIRED)
target_link_libraries(my_client PRIVATE turtle::endpoint)
```

```c
#include <turtle/endpoint.h>

/* my_*는 앱의 TLS 호출을 위 계약으로 제공하는 함수다. */
turtle_result run_benchmark_connection(void *prepared_tls)
{
    const turtle_endpoint e = {
        .conn = prepared_tls,
        .handshake_until = my_handshake,
        .write_plain = my_write,
        .read_plain = my_read
    };
    return turtle_run_endpoint(&e);
}
```

TURTLE을 `cmake --install build --prefix "$PWD/out/sdk"`로 설치한 뒤, **앱의 기존** CMake 설정에 `-DCMAKE_PREFIX_PATH=/절대경로/out/sdk`를 추가한다. 앱의 기존 명령행과 인증 옵션은 그대로 두고 [프로필 예](../examples/one-sided-s3.json)의 `target.argv`에 빌드한 앱과 실제 인자를 넣는다. `scenario`와 `auth`는 프로필에서 선택한다. `./bench.sh 내프로필.json 새결과폴더`가 상대 역할과 시나리오 입력을 준비한다. SDK를 호출하는 동안 stdin/stdout은 시험 평문 채널이므로 앱 진단은 stderr에 쓴다.

## 전송 훅에서 넘길 것

훅이 없거나 중간에 끊겨도 확인된 시나리오 결과와 첫 평문 읽기 시각은 남지만 완전한 벤치마크 표본은 아니다. 피어의 관측이나 패킷 캡처로 대상의 훅을 대신하지 않는다.

기존 [관찰 API](../include/turtle/observe.h)를 쓴다. BIO 또는 동등한 **TLS 라이브러리 입출력**을 관찰하면 소스 이름은 `"library_io"`다. 훅 장착 뒤 실행 전에 `turtle_observe_coverage("library_io", 1)`, 끝난 뒤 `turtle_observe_coverage("library_io", 0)`를 한 번씩 호출한다. 실제 송수신 진입과 반환은 다음처럼 짝을 맞춘다.

```c
/* 진입 훅: 이 호출의 상태에 begin을 보관한다. */
turtle_observe_stamp begin = turtle_observe_now();
/* 원래 전송 호출: 버퍼, 요청 길이, 재시도 및 반환값은 변경하지 않는다. */
/* 반환 훅: actual은 요청 길이가 아니라 실제 바이트 수 또는 실패값이다. */
turtle_observe_stamp end = turtle_observe_now();
turtle_observe_io(begin, end, "library_io", sent, requested, actual, buf, peek);
```

`sent`는 송신 1·수신 0이다. 버퍼는 관찰 동안만 빌리며, 실패·EOF·peek는 스트림을 전진시키지 않는다. 카운트만 제공할 때 `buf = NULL`이 가능하나 암호문 상세 분석도 가능한 것은 아니다. 한 번의 훅 호출이 한 패킷·레코드·핸드셰이크 메시지라고 가정하지 않는다. SDK와 분석기가 시각·카운트·바이트 범위를 관리한다.
