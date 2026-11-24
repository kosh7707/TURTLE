# OpenSSL 1:1 채팅

서버 터미널과 클라이언트 터미널이 로컬 TCP 연결 하나에서 실제 TLS 1.3으로 채팅한다.
모의인 것은 채팅 서비스이지 TLS가 아니다. TURTLE, 계측 훅, S0–S4 실행기는 아직 사용하지 않는다.

## 실행

POSIX 환경에서 OpenSSL 3의 라이브러리·개발 헤더·CLI, CMake 3.20 이상, C++17 컴파일러가 필요하다.

```sh
cd mock
cmake -S . -B build
cmake --build build
./build/chat_server             # 터미널 1
```

다른 터미널에서 `mock/build/chat_client`를 실행한다. 기본 주소는 `127.0.0.1:8443`이다.
누구든 먼저 한 줄을 보내면 상대 화면에 `peer> 내용`이 뜬다. 한 줄은 최대 4096바이트이며
`/quit` 또는 입력 EOF(Ctrl-D)로 종료한다. 서버는 연결 하나를 처리하고 끝난다.
포트가 사용 중이면 두 프로그램에 같은 포트 번호 하나를 인자로 준다.

첫 빌드가 `build/certs/`에 30일 유효한 로컬 개발용 인증서와 개인키를 만든다.
클라이언트는 해당 인증서를 신뢰하고 서버 이름 `localhost`를 검증한다. 클라이언트 인증서는 쓰지 않는다.
키는 소스에 포함하지 않는다. 별도로 빌드·설치한 OpenSSL 포크를 쓰려면 새 빌드 디렉터리를 구성할 때
`-DOPENSSL_ROOT_DIR=/포크의/설치경로`를 주고 CMake가 찾은 라이브러리 경로를 확인한다.

## 코드 읽는 순서

| 역할 | 호출 순서 | 함수 선언 | OpenSSL·TCP 구현 |
|---|---|---|---|
| 클라이언트 | [main.cpp](client/main.cpp) | [client.hpp](client/client.hpp) | [client.cpp](client/client.cpp) |
| 서버 | [main.cpp](server/main.cpp) | [server.hpp](server/server.hpp) | [server.cpp](server/server.cpp) |

이 함수들은 앱의 기존 동작을 나눈 것이지, 전부 프레임워크에 등록하라는 API 목록이 아니다.
포트 처리, `listen`/`connect`, 화면 출력이나 ML-KEM 내부 함수는 앱·구현체의 몫으로 남는다.

| 프레임워크가 알고 싶은 것 | 이 앱에서 확인할 지점 |
|---|---|
| **암호화된 전송 I/O 관측** | 두 `main`의 [`attach_socket_bio()`](endpoint.hpp). 여기서 `SSL_set_fd`가 SSL 세션과 TCP 소켓을 연결한다. 필요하다면 **첫 핸드셰이크 호출 전에** 개발자가 훅을 걸 수 있는 BIO 또는 동등한 전송 경계를 제공한다. `SSL_set_fd` 자체가 계측 훅은 아니다. |
| **인증 정책과 실제 핸드셰이크 결과** | 각 역할의 `configure_tls()`가 정책을 정하고, `handshake()`에서 실제 `SSL_connect` 또는 `SSL_accept`의 성공·실패가 결정된다. 현재는 서버 인증만 한다. mTLS 시나리오라면 시작 전 양쪽의 자격 증명·검증 정책을 적용하고, 서버에서 클라이언트 인증서 검증 성공까지 확인해야 한다. |
| **CAD/SAD를 언제 쓰고 무엇을 받았는가** | 공통 [chat.cpp](chat.cpp)의 `run_chat()`은 지금 키보드 입력을 송신 조건으로 삼는다. `write_plaintext()`는 `SSL_write_ex`의 결과를 받고, `read_peer_lines()`는 `SSL_read_ex`의 결과를 완전한 한 줄로 조립한다. 자동 시나리오에서는 키보드 대신 규칙이 송신을 지시하고, 수신 측이 기대한 메시지 전체를 검증해야 한다. 쓰기 성공이나 BIO 호출 횟수는 그 증거가 아니다. |

이 서버는 `SSL_accept()`가 **끝난 뒤에만** 채팅에 들어간다. 서버가 채팅 첫 줄을 먼저 쓸 수는 있지만,
클라이언트 Finished 전에 안내를 보내는 S2/S4의 기능까지 구현한 것은 아니다.

통합 검증: `ctest --test-dir build --output-on-failure`. 실제 두 프로세스 사이의 메시지,
정상 종료, 신뢰하지 않는 인증서와 잘못된 서버 이름의 거부를 확인한다.
