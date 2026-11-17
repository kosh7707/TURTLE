# 구현 검증

2026-11-17 현재 C++ 프레임워크를 새로 빌드하고 검증했다. 프레임 삽입·제거와 측정 경계를 유지한 상태에서 실행 제어·libpcap·사후 분석·perf 해석을 확인했다. 아래 링크의 `out/` 자료는 재생성 가능한 로컬 산출물이며 Git에는 포함하지 않는다.

| 검증 | 결과와 범위 |
|---|---|
| 별도 CTest | 35개 통과. 프레임·C 계약·분석·실제 TLS·외부 빌드·netem·중단·perf |
| 실제 TLS | OpenSSL 3.5.9·wolfSSL 5.9.4의 동종·교차 4조합 × 5프로파일, 20개 |
| TLS 버전 교체 | 같은 OpenSSL 연결 소스를 3.5.5로 빌드, Classical·긴 ML-DSA 체인 통과 |
| 구간·패킷 분석 | 큰 정수, 분할 Hello, 공유 비용, 시퀀스 순환, 부분 재전송·다중 레코드 패킷, 두 pcap 바이트 순서 |
| 실제 netem | 기준·지연/손실/속도 구성 각 3회. 모두 TLS·구간·네트워크 완료 |
| 중단 | 설정 완료 뒤 SIGTERM. 시도 보존, 추가 실행 중단, 소유 네임스페이스 정리 |
| 실제 perf | 두 라이브러리 각각 카운터·cpu-clock:u·cycles:u, 6개 시험 통과 |
| 독립 보고서 | manifest·분석 JSON만으로 보고서 재생성, 두 출력의 바이트 일치 |
| Wireshark | 새 pcap과 C++ 분석을 TShark로 독립 대조 |
| 정적 검사 | 부품의 비순환 의존·공개 계약 경계, 23개 C++ 번역 단위의 clang-tidy |
| ARM64 | CLI·OpenSSL·wolfSSL 엔드포인트의 AArch64 ELF 교차 빌드·링크 |

[CTest 로그](../../out/verification/ctest.log), [정적 검사](../../out/verification/static.log), [ARM64 확인](../../out/verification/arm64.log), [보고서 검증](../../out/verification/report.log), [TShark 결과](../../out/runs/wireshark-final/verification.json), [종합 기록](../../out/verification/summary.json)에 근거를 남긴다.

## 네트워크 관측

실제 netem 시험은 ML-DSA 인증서 체인과 X25519MLKEM768을 사용했다. 기준 구성도 같은 세 네임스페이스·두 veth 배치다. 조건 구성에는 방향별 5 ms 지연, 10% 손실, 10 Mbit/s와 netem seed 7을 설정했다.

기준 세 시도의 송신 측 재전송 바이트는 클라이언트·서버 모두 0이었다. 조건 세 시도에서는 각각 클라이언트/서버 `4/1448`, `1410/2658`, `0/1214`바이트의 재전송을 관측했다. qdisc 제거 카운터는 각 조건 시도에서 방향별 5였으며 재전송 바이트나 개별 패킷 제거 원인과 같은 값으로 해석하지 않는다.

[실행 manifest](../../out/tests/native/artifacts/netem/run/manifest.json), [비교 보고서](../../out/runs/netem-report/report.html), [중단한 시도](../../out/tests/native/artifacts/interrupted/run/manifest.json)를 보존한다. 이 작은 검증 표본으로 구현 간 성능 우열을 결론내리지 않는다.

## 독립성

공식 소스에서 Python 연결을 끈 perf 7.0.14를 빌드했다. TURTLE과 perf의 동적 연결 목록에 libpython이 없다. JSON·libpcap의 캐시 기반 준비 도구도 새 디렉터리에서 확인했다. [의존성 준비 로그](../../out/verification/dependency-preparation.log)

격리 환경에서는 Python 실행 파일·libpython·tcpdump를 사용할 수 없게 가리고 `tools/`와 외부 작업 공간을 복사하지 않는다. 네트워크를 분리한 뒤 CMake·Ninja로 소스와 별도 테스트를 빌드하고 실제 TLS·netem·중단·perf를 포함한 33개 시험, 설치한 CLI의 재분석을 수행한다. OpenSSL 대체 버전 2개 시험은 호스트의 35개 시험에 포함한다. [격리 검증 기록](../../out/verification/isolated/verification.json)

## 검증 한계

현재 실행 호스트는 Linux/WSL2다. ARM64는 교차 컴파일·링크와 ELF 형식까지 확인했으며 실제 보드에서 TLS·netem·PMU를 실행하지 않았다. wolfSSL의 GCC 15 ARM64 빌드는 upstream AES 경고의 오류 승격만 해제했다. [준비 옵션](dependencies.md)에 기록했다.

clang-tidy는 `clang-analyzer-*`와 `bugprone-use-after-move`를 사용했다. 의존성 헤더의 억제된 경고는 로그에 남으며 모든 종류의 정적 분석을 수행했다는 뜻은 아니다. Wireshark 검증은 TShark로 수행했으며 GUI 조작 자동화를 성공 조건으로 두지 않았다.

측정값의 의미와 계측 영향은 [방법론](OVERVIEW.md)의 경계와 한계를 따른다. TLS 시나리오 성공, 구간 완료, 네트워크 완료, perf 완료와 정상 종료 상태는 별개다.
