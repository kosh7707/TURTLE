# 이미 빌드한 TLS 앱 계측하기

TLS 라이브러리 소스로 양쪽 실행 파일을 만들려면 [기본 제출 안내](../README.md)를 보세요. 이 가이드는 앱의 기존 빌드를 유지하고 [TURTLE SDK](endpoint.md)만 연결할 때 사용합니다.

## 클라이언트와 서버 프로필 실행

Linux에서 C11/C++20 컴파일러와 CMake 3.20+, Make 또는 Ninja가 필요합니다. 이 예시는 OpenSSL 3.5+ 개발 헤더·라이브러리와 `openssl` 명령을 사용합니다. 시스템 OpenSSL이 없다면 같은 버전의 SDK를 준비한 뒤 CMake에 `OPENSSL_ROOT_DIR`을 지정하고 해당 `openssl` 명령을 `PATH`에 둡니다. 외부 JSON 라이브러리는 사용하지 않습니다. 패킷 캡처가 필요한 연구용 빌드는 libpcap 개발 파일을 준비하고 CMake에서 `-DTURTLE_WITH_PCAP=ON`으로 명시합니다. 기본 설정은 캡처 없이 동작합니다.

저장소 루트에서 실행합니다. 프로필에서 상대역을 생략하면 설치된 **참조 피어**가 필요합니다. 아래는 이 예시를 위해 기본값이 꺼져 있는 참조 피어를 명시적으로 켭니다.

```sh
work=$(mktemp -d)
cmake -S . -B "$work/turtle" -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF -DTURTLE_BUILD_REFERENCE=ON &&
cmake --build "$work/turtle" --parallel 2 &&
cmake --install "$work/turtle" --prefix "$work/sdk" &&
cmake -S tests/endpoint-integration -B "$work/app" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$work/sdk" &&
cmake --build "$work/app" --parallel 2
```

다음 프로필은 각 역할에서 S0(TLS 1.3, 서버 인증, 루프백)을 예열 한 번과 본 시도 열 번으로 실행합니다. 계측 대상은 참조 피어가 아니라 **설치한 SDK를 사용해 별도 빌드한 [C 앱](../tests/endpoint-integration/consumer.c)**입니다.

```sh
export PATH="$work/app:$PATH"
"$work/sdk/bin/turtle" run docs/examples/openssl-client-s0.json "$work/client-s0" &&
"$work/sdk/bin/turtle" run docs/examples/openssl-server-s0.json "$work/server-s0"
```

SDK 경로에서는 콘솔부터 읽습니다. `Details:`가 가리키는 `analysis.json`은 다시 분석하는 데 쓸 수 있습니다. **연결 성공, 시간·카운터 가용 여부, 성능 표본 적격 여부는 별개입니다.** 콘솔에 보이는 개별 시간은 평균이 아니며, CPU 카운터가 없는 호스트에서 연결이 성공해도 성능 표본이 없을 수 있습니다. 아래는 TLS를 다시 실행하지 않고 원자료를 재분석합니다. 옛 버전의 결과를 보존해야 한다면 원본 대신 사본에서 실행하세요. 현행 판독기는 S2 시간 구간을 이전 버전과 다르게 판정할 수 있습니다.

```sh
"$work/sdk/bin/turtle" analyze "$work/client-s0"
```

## 내 앱에 붙이기

앱은 [SDK 계약](endpoint.md)에 따라 기존 소켓과 TLS 콜백을 전달합니다. 앱의 CMake 구성에서 설치된 `TURTLE` 패키지를 찾고 `turtle::endpoint`를 링크하세요. 이 경로는 `implementations/`을 읽지 않습니다.

- [클라이언트 프로필](examples/openssl-client-s0.json) 또는 [서버 프로필](examples/openssl-server-s0.json)에서 `target.argv`를 실제 실행 명령으로 바꿉니다. `peer.argv`로 자신이 준비한 상대역을 지정할 수도 있습니다.
- `scenario`와 `auth`로 시나리오·인증을 설정합니다. 앱 페이로드나 네트워크 조건을 바꾸는 설정도 SDK 프로필에 있습니다. 예를 들어 [단방향 계측 S3 프로필](examples/one-sided-s3.json)의 `application`은 요청과 응답을 정합니다. 연결 후 이미 빌드된 TLS 엔진에서 어떤 그룹·suite를 허용할지는 앱의 TLS 설정입니다.
- 계측기는 측정 중 관측 기록을 메모리에 쌓고, 정상 프로세스 종료 때 최종 기록과 완료 표식을 내보냅니다. 앱이 계속 실행되거나 `_exit()`로 종료한다면 모든 관측이 끝난 뒤 측정 구간 밖에서 동시 콜백 없이 `turtle_observe_flush()`를 호출하세요. 시작 전 준비 기록이나 `end` 이벤트만으로는 완료된 증거가 되지 않습니다.
