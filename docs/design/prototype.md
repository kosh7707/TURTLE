# 공통 실행·계측 계약

공개 ABI 3, TLS 원자료 schema 3, 측정 계약 개정 4의 설명입니다. 의존성 스크립트는 각 `instrumentation.patch`를 적용하고 `.deps/manifests/`에 원본 판·빌드 설정·패치 해시를 남깁니다. 원자료 `declaration`도 출처와 해시를 보존합니다. 설치 기록과 패치 해시가 다르면 의존성을 다시 빌드해야 합니다.

## 시행과 시나리오

서버 수신 대기 소켓만 미리 만듭니다. 모듈·컨텍스트 준비 뒤 시행 준비 신호를 교환하고 새 connect/accept를 수행합니다. TLS 역할은 `RLIMIT_NPROC=0`을 유지하지만 새 소켓을 위해 `RLIMIT_NOFILE=0`을 적용하지 않습니다. 모의 CA는 [별도 서비스 계약](../experiments/mock-ca.md)을 따릅니다.

| 설정 | 서버 | 클라이언트 |
|---|---|---|
| `handshake` | ClientFinished 처리와 API 완료 | ClientFinished 송신과 API 완료 |
| `server-ping` | ServerFinished 제출 뒤 Ping, 이후 정상 핸드셰이크 완료·Pong 수신 | 핸드셰이크 완료 뒤 Ping 수신·Pong |
| `finished-ping` | ServerFinished와 Ping을 같은 출력 배치로 제출, 이후 정상 완료 | 핸드셰이크 완료 뒤 Ping 수신·Pong |
| `client-request` | 핸드셰이크 뒤 요청 수신·응답 | 핸드셰이크 뒤 요청·응답 수신 |

기본 시나리오는 `client-request`입니다. `--client-bytes`, `--server-bytes` 또는 TLS 프로필의 `client_application_bytes`, `server_application_bytes`로 방향별 크기를 정합니다. 생략하면 `application_bytes`이며 기본 32바이트입니다. 양쪽은 고정 패턴을 검증합니다. HTTP나 사용자 콜백은 없습니다. 순수 핸드셰이크는 `scenario_completed=true`, `application_verified=false`입니다.

`ApplicationWriteReady=4`는 서버의 응용 쓰기 준비와 전체 완료를 구별합니다. `Complete=2`, `Failed=3`의 ABI 숫자는 유지합니다. 상호 인증의 조기 Ping은 클라이언트 인증 완료 전에 보내는 시험 페이로드입니다. 이후 ClientFinished와 인증을 끝까지 검증하며 실패 시 무효입니다. 클라이언트 0-RTT나 세션 재개는 켜지 않습니다.

출력 버퍼는 측정 전에 확보합니다. `OUTPUT_ACCEPTED`는 프레임워크 버퍼 수용이고, 성공한 `IO_SEND_RETURN` 바이트만 실제 스트림에 누적합니다. 부분 쓰기·EAGAIN 뒤에도 `batch_id`를 유지합니다. 출력 배치, TLS 레코드와 TCP 세그먼트는 다른 단위입니다.

`server-hello-first`는 ServerHello를 소켓에 제출한 뒤 암호화된 서버 flight를 구성합니다. OpenSSL에는 명시적 flush를 넣었고 wolfSSL·Mbed TLS의 해당 기본 경로는 이미 이 순서입니다. 결합 시나리오에서도 ServerHello는 먼저 제출하고 나머지 flight와 Ping을 묶습니다. 정책은 추적 활성화와 독립입니다.

## 실제 내부 사건

| 구현 | 관측 위치 | 해석 한계 |
|---|---|---|
| OpenSSL 3.5.4 | 상태 머신의 메시지 구성·처리·후처리, `tls13_cipher` | 별도 상태 준비·정리 전체를 포함하지 않습니다. |
| wolfSSL 5.8.2 | Hello·인증서·CertificateVerify·Finished·확장의 `DoTls13*`, 레코드 암복호화, 송신 함수와 그 안의 생성 구간 | `library_message_write`는 넓은 송신 구간입니다. 추가한 `message_generate`는 레코드 암호화·I/O 전에 닫으며 같은 비용을 두 번 더하지 않습니다. |
| Mbed TLS 3.6.4 | Hello·EncryptedExtensions·CertificateRequest·인증서·CertificateVerify·Finished 바디 생성과 fetch 뒤 처리, 레코드 암복호화 | 바디 밖의 prepare/finalize·키 준비와 공통 TLS 헤더 구성은 생성 구간 밖입니다. |
| BiTHaC | wolfSSL 위치와 `CISSC_SendCachedTls13Certificate` | `cached_certificate_write`는 실제 연구 경로이며 레코드·입출력도 포함합니다. |

wolfSSL의 추가 생성 구간은 스택 객체가 소유하고 모든 정상 반환·재시도에서 닫습니다. 인증서가 여러 레코드로 나뉘면 조각별 구간을 기록합니다. Hello의 평문 레코드 헤더·transcript 갱신과 함수 안 준비 비용 일부가 포함되지만, 암호화 메시지의 `BuildTls13Message`와 소켓 송신은 제외합니다. Mbed TLS는 바디 함수만 감싸므로 두 구현의 생성 시간이 동일한 연산 목록을 포함한다는 뜻은 아닙니다. 키 준비·transcript 작업 등 다른 위치의 비용은 전체 역할 구간에 남으며 메시지에 임의 배분하지 않습니다.

패치 판은 원자료의 해시로 구별합니다. BiTHaC의 고정 5.7.0 패치는 처리·레코드·실제 캐시 송신을 관측하며 위 wolfSSL 5.8.2의 생성 구간을 제공하지 않습니다. `tests/integration/prototype.py`는 세 표준 라이브러리의 해당 메시지 종류, 사건 짝과 생성 구간 안에 record 암복호화·I/O가 없는지를 실제 TLS로 검사합니다.

프레임워크 소유 `TraceSink`에 고정 크기 사건을 전달합니다. 메시지 ID는 연결·연산 종류·메시지 종류로 구성해 비차단 재시도를 연결합니다. 레코드 ID는 암복호화 호출 순번이며 오프라인 TLS 레코드 번호와 같다고 가정하지 않습니다. 지원 위치가 다르므로 모든 구현의 내부 구간을 동일 연산 집합으로 묶을 수 없습니다. 내부 구간은 중첩될 수 있으므로 모두 합산하면 비용을 중복해서 셀 수 있습니다.

공개 평문 알림은 시각 없는 메시지 대조 자료입니다. 상세 시간은 패치의 실제 작업 전후 표식에서만 만듭니다. 시간 모드에서는 내부 사건을 기록하지 않지만 패치 분기·기본 경계·스트림 기록의 부담은 남습니다. 무계측 성능이라고 부르지 않습니다.

## 원자료와 보고서

모듈, 셋업, TCP 연결·accept, 연결 준비, API 완료, 페이로드 준비, 응용 쓰기·첫 바이트·전체 읽기, 출력 수용·flush와 내부 구간을 기록합니다. 컨텍스트 해제는 마지막 연결의 `teardown` 호출입니다. 보고서의 연결별 `prototype.windows`는 다음 구간을 제공합니다.

- 클라이언트 연결 준비 시작 또는 TCP 연결 시작→ClientFinished 레코드의 소켓 제출 완료.
- 서버 첫 TLS 수신 반환→실제 내부 ClientFinished 처리 완료. 내부 추적을 끄면 미지원입니다.
- 클라이언트 Ping 수신 완료→Pong 제출, 서버 Ping 쓰기 시작→Pong 수신 완료.
- 클라이언트 요청 쓰기→응답 첫 바이트·전체 수신, 서버 요청 수신 완료→응답 제출.
- 모듈·컨텍스트 셋업은 연결 0에만 남고 이후 연결에는 해당 없음으로 표시됩니다.

각 구간은 `available`, `unsupported`, `not_applicable`, `missing`과 값이 없는 `null`을 구별합니다. `internal_spans_complete`는 선언한 사건의 짝이 맞았다는 뜻이며 라이브러리 전체를 관측했다는 뜻이 아닙니다. 추적을 끈 빈 목록에는 완전성을 주장하지 않습니다.

개정 4의 `primary_window`는 클라이언트 첫 핸드셰이크 호출 또는 서버 첫 TLS 수신부터 시나리오의 마지막 TLS API 성공 반환까지입니다. 순수 핸드셰이크는 `handshake_step`이 `Complete`를 반환한 `CALL_END`, 응용 시나리오는 역할의 마지막 전체 송신·수신을 마친 `CALL_END`에서 끝납니다. 수신에는 TLS 무결성 검증·복호화·응용 버퍼 전달이 포함됩니다. 최종 시험 패턴 대조와 소켓 정리는 종료점 밖입니다. 상세 역할 표는 [실행 문서](runtime.md#시나리오의-종료-개정-4)를 따릅니다. `end_sequence`가 종료점을 지정합니다. API 완료·내부 Finished·소켓 제출은 다른 지표입니다. 순수 핸드셰이크와 응용 실행에서 추출한 구간은 시나리오 조건으로 분리합니다. 종료 사건이 없으면 다른 사건으로 추정하지 않습니다.

```sh
JOBS=4 scripts/build-deps.sh all
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DTURTLE_ADAPTER_LINKAGE=module -DTURTLE_BUILD_MODULES=ON -DTURTLE_WITH_OPENSSL=ON \
  -DTURTLE_WITH_WOLFSSL=ON -DTURTLE_WITH_MBEDTLS=ON
cmake --build build --parallel 4
scripts/make-pki.sh pki/default
build/turtle-local --client openssl --server mbedtls --pki pki/default \
  --scenario finished-ping --send-policy server-hello-first \
  --client-bytes 32 --server-bytes 32 --samples 1 --connections 1 --warmups 0 \
  --mode trace --no-affinity --no-perf --output results/prototype
```

각 역할 JSONL을 `turtle-interpret`로 해독한 뒤 `turtle-report`를 실행합니다. `--no-affinity`는 개발 예제의 명시 조건이며 본 실험 배치를 대신 정하지 않습니다. 선언하지 않은 시나리오·정책은 중단하며 패치 없는 시스템 OpenSSL의 제한된 지원과 고정 계측 빌드를 구별합니다.
