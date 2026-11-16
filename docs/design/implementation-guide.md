# 구현자 안내

공개 계약은 [implementation.h](../../include/turtle/implementation.h) 하나입니다. C와 C++에서 사용할 수 있고 코어와 구현체 소스를 함께 컴파일합니다. ABI 버전 검사, `dlopen`, 바이너리 플러그인은 없습니다. 헤더가 바뀌면 함께 다시 빌드합니다.

새 구현체는 `turtle_register()`에서 다음 연산을 제공하는 함수표를 반환합니다.

| 연산 | 책임 |
|---|---|
| support | 이름, 원본 버전, 실제 기법 설명 |
| create/destroy_context | 인증서·키·난수·캐시 등 컨텍스트 수명 |
| create/destroy_connection | 연결 상태와 구현체 버퍼 수명 |
| transition | 시작, 송수신 전처리, transcript 갱신과 후처리·키 전환, 로컬 handshake 종료 |
| assemble | 선택한 논리 메시지의 헤더를 포함한 바이트 조각 생성 |
| process | 선택한 논리 메시지의 조각 소비와 메시지 처리 |
| protect/unprotect | TLS 5바이트 헤더를 포함한 정확히 한 레코드 처리 |
| storage | 측정 종료 뒤 구현체의 버퍼·캐시 저장 공간 조회 |
| result/error | 실제 인증·전체 handshake·기법 증거와 오류 설명 |

`assemble`은 첫 호출의 offset=0에서 생성하고 이후 offset에서 기존 결과를 제공할 수 있습니다. `MORE`는 양의 진행량이 필요합니다. `DONE`인 연산을 다시 호출하지 않습니다. 현재 실행기는 완성된 메시지를 재조립한 뒤 최대 4 KiB씩 처리 함수에 제시합니다. `last=1`은 제시한 범위가 메시지 끝까지 닿는다는 뜻이며, 그 범위의 일부만 소비하면 다음 호출에도 다시 1이 올 수 있습니다. 실제 누적 소비가 메시지 끝에 도달할 때 `DONE`을 반환합니다. 조각을 구현체 버퍼에 누적하고 마지막 호출에서 native 파서를 한 번 실행할 수 있습니다. 바이트 뷰는 호출 동안만 유효합니다. 옵션 문자열은 현재 엔드포인트가 컨텍스트 수명 동안 유지합니다.

`PREPARE_RECEIVE`는 완성된 메시지 뷰를 받습니다. 라이브러리에 필요한 transcript 순서와 Finished 검증 준비를 이 단계에 두고, 처리 후 키 전환은 `COMMIT_RECEIVE`에서 수행합니다. 송신은 본문 생성 전에 필요한 작업을 `PREPARE_SEND`, 기록과 키 전환을 `COMMIT_SEND`에 둡니다. 이 비용은 모두 전환 사건으로 계측합니다. 구현체가 다음 메시지나 전체 handshake까지 진행하면 계약을 위반합니다.

`COMMIT_SEND`는 메시지 조립 완료를 전제로 하며 소켓 제출 완료를 뜻하지 않습니다. 묶음 정책에서는 transcript를 먼저 갱신하고 다음 메시지를 조립한 뒤 함께 레코드로 보호할 수 있습니다. 키 전환이 있는 Hello·Finished에서는 프레임워크가 남은 평문을 이전 키로 보호한 다음 `COMMIT_SEND`를 호출합니다. 레코드에 속한 모든 메시지의 비용을 각 메시지의 전환에 다시 더하지 않습니다.

성공 결과는 실제 TLS 버전·전체 handshake·인증서 존재·검증 결과를 사용합니다. 지원하지 않는 버퍼·캐시 용량은 inventory의 가용 비트를 끄고, 알려진 실제 0과 구별합니다. `storage_available`의 비트 1·2·4는 메시지 버퍼·레코드 버퍼·기법 캐시의 요청 저장 공간을 뜻합니다. 이 합은 구현체 전체 메모리가 아닙니다.

다음 등록만으로 역할별 실행 파일이 생성됩니다.

```cmake
turtle_implementation(my_backend SOURCES message.c
  INCLUDES "${native_source}/include"
  LIBRARIES "${native_build}/libnative.a")
```

`implementations/my_backend/CMakeLists.txt`를 추가하고 `scripts/build.sh 'my_backend'`로 선택합니다. 현재 메시지 순서와 결과 계약을 따르는 구현체라면 네트워크, 시계, 사건 기록과 보고서를 수정하거나 계측 콜백을 작성할 필요가 없습니다. native private 헤더는 구현체 디렉터리에서만 사용합니다.

현재 `support`는 설명 문자열이며 자동 지원 협상표가 아닙니다. 레코드 암복호화는 한 번의 호출로 완료해야 하고, 조립·처리의 `MORE`로 네트워크나 비동기 연산 대기를 요청할 수 없습니다. 응용 데이터 생성·검증은 공통 실행기가 담당합니다. 새로운 메시지 순서·키 전환·기법 전용 결과를 추가하는 작업은 기존 함수 교체와 범위가 다르며 [설계 논의](discussion.md)에서 다룹니다.

## ClientHello 한 함수 교체

[clienthello.c](../../implementations/openssl-padded/clienthello.c)는 공통 헤더만 포함하고 OpenSSL 기본 함수표의 `assemble`만 교체합니다. 완성된 ClientHello에 16바이트 padding extension을 추가하고 길이를 갱신합니다. 나머지 메시지, 레코드, 키 전환과 인증은 기존 함수표를 사용합니다. 큰 ClientHello가 첫 버퍼에 들어오지 않으면 원본 메시지를 그대로 사용한다는 제한을 코드에 명시했습니다.

```sh
scripts/build.sh 'openssl;mbedtls;openssl-padded'
python3 scripts/run.py --client openssl-padded --server mbedtls \
  --mutual-auth --depth white-box --stream --output results/clienthello
```

이 예제는 원본 함수의 출력을 실제로 바꾸며, Mbed TLS 서버와 전체 인증·암호화 응용 교환을 완료하는 시험이 있습니다. 예제 성공을 임의의 ClientHello 변경이 유효하다는 주장으로 넓히지 않습니다.
