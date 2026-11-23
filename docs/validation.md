# 라이프사이클 합격 시험 — x86-64 Linux

아래 결과는 이 작업에서 새로 연 TLS 연결의 결과다. 보관 PCAP 검산, 정지 능력 시험, 예열, 외부 추적 실행은 **별도 증거**이며 일반 성능 표본이 아니다. 경로·시도 ID·정확한 수치와 해시는 [검증 목록](evidence/validation.json)에 있다.

| 질문 | 수행한 시험과 결과 |
|---|---|
| 외부 개발자가 코어 수정 없이 사용할 수 있는가? | SDK를 설치하고 두 어댑터의 소스 디렉터리를 각각 복사해, 별도의 CMake 프로젝트에서 설치된 공개 계약·엔드포인트와 해당 TLS 라이브러리만으로 빌드했다. 그 두 실행 파일로 아래 직접 발급 mTLS S3 예열 1회와 본 측정 3회를 완료했다. `implementation_registration`은 C 함수표와 필수 query 누락도 검사한다. |
| 공개 암호문 훅과 실제 소켓 호출이 일치하는가? | 8개 프로세스(네 구성 각각 예열·측정)에서 `strace`의 성공한 송수신 **7,525회 / 29,664 B / 120레코드**를 별도로 조립했다(종료 알림 포함). 요청량, 반환량, 실제 바이트, 소켓 호출과 상위 OpenSSL BIO 또는 wolfSSL 콜백, 분석기가 보고한 헤더·본문 구간을 대조했다. 헤더 분할, 레코드 분할, 한 호출의 여러 레코드를 모두 관측했다. |
| perf 수치와 함수 표본이 실제로 수집되는가? | 양쪽 라이브러리를 각각 측정 대상으로 삼아 실제 PMU와 stock `perf record/script` 시험 6개를 수행했다. 시나리오 구간의 cycles·instructions·enabled/running 시각차와 **이름이 확인된 함수 표본**이 있다. 카운터·프로파일 수집의 지연은 일반 분포에 합치지 않았다. `recording_cost`는 동일한 mTLS S3/TCP 구성에서 기록 끔·기본·상세 각각 5개의 독립 표본을 생성했다. 이 작은 표본으로 기록 비용의 보편적 크기·순서를 주장하지 않는다. |
| TCP 순번이 소켓 기록 이상의 정보를 주는가? | 제공된 보관 S2 PCAP의 독립 검산 결과가 저장된 기준 JSON과 바이트 단위로 일치했다. 새 루프백 및 netem 연결에 대해서도 TShark로 패킷, 스트림 범위, 반복 바이트, ACK/SACK을 독립 검산했다. S3 손실 사례에서 서버가 측정한 **9,824 B**의 반복 범위는 레코드 5·6·8에 각각 2,694·150·6,980 B 걸쳤다. 지연을 준 S2에서 CF 종료 레코드 5의 첫 바이트를 담은 **특정 TCP 사본**의 ACK 오프셋 2,232는 서버 안내 레코드 8 끝까지 상대 TCP에 들어왔음을 증명했다. 이 두 결론은 소켓 호출만으로는 낼 수 없다. ACK가 짧거나 캡처가 불완전하면 반대 순서를 추정하지 않는다. |
| 시나리오와 예열은 분리되는가? | OpenSSL 3.5.9 / wolfSSL 5.9.4 네 조합 × S0–S4 × 서버 인증/mTLS × 계측 역할 2개 = **80개 구성**. 각각 예열 1회와 유효 본 측정 1회를 확인했다. S2/S4에는 추가로 정지 능력 시험 총 32회가 있다. 별도 hybrid, ML-DSA, 인증서 체인, 부분 I/O 연결도 검증했다. 잘린 요청과 틀린 요청에는 응답하지 않았으며, 예열 협상 불일치는 그 구성만 차단했다. 동등한 의미의 Finished 경계가 다른 레코드 번호에 놓이는 경우, 누락된 필수 훅, 선택 캡처 부재, 실패·중단·새 ID로의 재시도도 시험했다. |

## 짧은 원자료 재생

[직접 발급 mTLS S3 원자료](evidence/mtls-s3-loopback.tar.gz)에는 양쪽 역할 결과, 측정 측 사건, 명세와 해시, 판정이 있다. 키·인증서·라이브러리 바이너리는 포함하지 않았다. 재분석에는 네트워크나 TLS 라이브러리가 필요하지 않다.

~~~sh
mkdir out/replay-s3
tar -xzf docs/evidence/mtls-s3-loopback.tar.gz -C out/replay-s3
out/build/native/turtle analyze out/replay-s3
python3 tools/report/report.py out/replay-s3 out/replay-s3-report
~~~

첫 **본 측정**(`attempts/00001`)에서 사건 2의 핸드셰이크 호출 시작은 2,962,092,907,861 ns, 사건 7의 응답 평문 읽기 반환은 2,962,095,317,761 ns였다. 두 사건의 차이 **2,409,900 ns**가 해당 시도의 `scenario_wall_ns`다. 해당 응답 전체와 양쪽 인증의 검증은 성공 조건이지만 끝 시각을 뒤로 밀지 않는다.

[새 TCP 사례 원자료](evidence/tcp-cases.tar.gz)에는 S2 선송신·S3 손실 두 배치의 원래 PCAP, 엔드포인트 사건과 별도 검산 JSON이 있다. 캡처 권한 없이 다음과 같이 재검산할 수 있다(읽기용 libpcap, 독립 검산용 TShark 필요).

~~~sh
mkdir out/replay-tcp
tar -xzf docs/evidence/tcp-cases.tar.gz -C out/replay-tcp
for batch in s2net loss99; do out/build/native/turtle analyze "out/replay-tcp/$batch"; done
python3 tools/wireshark/check_lifecycle_capture.py out/replay-tcp/s2net/attempts/00002
python3 tools/wireshark/check_lifecycle_capture.py out/replay-tcp/loss99/attempts/00001
~~~

## 다시 수집하기

- [빌드와 CTest 설정](../README.md#외부-어댑터와-재현-시험). 네트워크·perf 시험까지 활성화한 빌드의 전체 로그: `out/ctest-final.log`. PCAP/PMU를 모두 뺀 빌드: `out/no-observers-final.log`. 각 통합 시험은 자체 `artifacts/<시험명>/spec.json`, 인증서 발급 내역과 `run/`을 남긴다.
- BIO 대조: [검산기의 사용법](../tools/verify_socket_trace.py). 상세 mTLS S3의 양쪽 라이브러리 및 계측 역할을 바꾸고 `io_chunk=0`, `2`를 함께 실행한다. 이번 독립 추적의 명세·PID별 원본·검산 결과는 `out/trace-acceptance.OzYx9Q/`에 있다.
- perf 원본: `out/test/artifacts/perf_*/run/attempts/`. 카운터는 `counters.json`, 프로파일은 `perf.data`, `perf.script.txt`, 빌드 ID·보존 심볼 파일을 함께 남긴다. 실행 시간이 0이거나 권한이 없는 구간을 실제 0 cycles로 보관하지 않는다.
- 이 증거의 범위는 **x86-64 Linux의 로컬 또는 격리된 IPv4 TCP**다. 실물 ARM 보드, 다른 TLS 버전이나 임의의 외부 서비스에 대한 성능 보증이 아니다.
