# 메시지 실행 프레임워크 검증 기록

검증일은 2026-11-13입니다. 의존성부터 다시 빌드한 오프라인 검증에서 CTest 6개 전부, 정적 검사, ML-KEM 오브젝트 검사, 기본 TLS 실행과 보고서 생성이 통과했습니다. CTest 실행 시간은 69.54초입니다. 각 명령의 종료 코드는 [오프라인 검증 원장](../../artifacts/build-history/2026-11-16/build-message-final/verification.json)에 있습니다. 개발 중 생성한 다른 디렉터리의 성공·실패를 이 기록의 표본에 합치지 않습니다. 아래 산출물은 이 작업 공간에 보존한 로컬 검증 자료입니다.

[완료 감사 원장](../../results/message-final/audit.json)은 현재 소스 61개의 해시, 새 빌드의 엔드포인트 바이너리 16개, 수집·비교 실행 38개의 바이너리 출처와 아래 결과를 다시 대조한 기록입니다. 큰 인증서의 실제 교차 실행에서도 양쪽 엔드포인트 6개의 모든 메시지 조각 범위를 확인했습니다.

2026-11-16에는 활성 경로와 과거 검증본을 분리했습니다. 아래 오프라인 검증본의 내용은 유지하고 링크만 현재 보존 위치로 갱신했습니다. 당시 JSON 안의 절대 경로는 수정하지 않았습니다. 이동·생성물 정리 내역은 [작업 공간 관리](workspace.md)에 있습니다. 이 기록의 기능 검증 성공은 현재 자동 비교 조건에 모든 실행 환경·빌드 차이가 포함된다는 뜻은 아닙니다. 그 범위는 [설계 문서](../design/architecture.md)에 명시했습니다.

## 요구사항별 완료 감사

최신 사용자 계획을 다음 항목으로 대조했습니다. 기능 완료, 실제 실행 증거와 관측 가용성을 구별하며 미지원 관측을 구현 완료의 증거로 쓰지 않습니다.

| 요구사항 | 구현과 검증 근거 |
|---|---|
| 독립 새 구조·소스 연결·호환 계층 제거 | 공개 계약은 `include/turtle/implementation.h` 하나이며 C 함수표와 불투명 핸들을 사용합니다. `cmake/Implementation.cmake`로 구현체별 양쪽 실행 파일을 만듭니다. 정적 검사가 내부 헤더 참조·순환 의존·동적 로더·전체 handshake API 호출을 검사합니다. |
| 프레임워크의 메시지·레코드·I/O 통제 | `src/execution`이 단계 순서, 조각 진행, 묶음·분할, 재시도와 완료를 소유합니다. 구현체에 소켓·시계·계측기 콜백이 없습니다. 결정적 시험과 실제 576조건의 송수신·복호화 바이트 대조가 근거입니다. |
| transcript·키 도출·후처리 비용 | 명시적인 PREPARE/COMMIT/BEGIN/FINISH 전환에 native 작업을 연결했습니다. 묶음에서 transcript 갱신과 보호 키 전환의 순서를 따로 지키며 전환 비용을 원자료에 남깁니다. 상세 구간의 비중첩을 검사합니다. |
| 네 시나리오·두 인증·두 깊이 | 세 기본 라이브러리의 모든 동종·교차 조합에서 검증합니다. 두 깊이는 동일 실행기를 사용하며 Finished+Ping의 배치 일치와 server-ping의 배치 분리를 검사합니다. |
| 실제 native 경계와 외부 상호운용 | 각 라이브러리에 내부 경계 패치를 적용했습니다. 전체 인증·암호화 교환을 완료하며 수정하지 않은 외부 TLS 구현과 양쪽 역할·인증의 12조건을 검증합니다. |
| 큰 메시지·부분 진행·부분 송신 | 약 34KB 인증서, 최대 약 64KB 응용 메시지, 두 레코드 크기와 부분 I/O를 검증합니다. 조립·처리의 일부 소비·생산과 부분 쓰기 중 조립·암호화 재실행 방지는 결정적 시험으로 확인합니다. |
| 준비·첫 사용·재사용과 비용 귀속 | 컨텍스트·연결·수신 소켓·조회·TCP 준비와 시나리오를 구별합니다. 첫 사용은 실제 첫 연결에만 계산합니다. 공유 레코드·I/O 비용을 메시지마다 복제하지 않습니다. 필수 측정 누락은 null입니다. |
| 식별자·정수·가용 상태·원자료 | 실행·컨텍스트·연결·역할·메시지·레코드·배치 ID, 정수 시각·계수와 바이트 범위를 JSONL로 남깁니다. 큰 정수, 미수집과 0의 차이, 새 계약 판독만 허용하는 보고서 시험을 통과합니다. |
| ML-KEM·BiTHaC | 실제 KEM 연산·내부 dispatch와 CI·SSC 사용을 확인합니다. 같은 기반의 비교, 빈 캐시·재사용, 캐시 미지원 상대와의 반복 연결, 큰 인증서와 전체 인증을 검증합니다. |
| MockCA | 독립 합성 객체 조회와 고정 저장본의 검증·삽입 후 동일 TLS 실행기를 사용합니다. 서비스와 양쪽 엔드포인트의 ID·시계·비용을 따로 기록합니다. |
| netem·패킷·커널·CPU 표본 | 아래 실제 수집 결과에서 적용값·누락·바이트 대응·손실 종류·소유 자원 정리와 바이너리 출처를 확인합니다. CPU 표본을 함수 호출 시간으로 환산하지 않습니다. |
| 통계·재현·연구자 사용 경로 | 저장한 seed의 실행 순서, 독립 컨텍스트 표본, 연결 위치별 StQ·부트스트랩을 실제 비교 자료로 확인합니다. 공개 헤더와 ClientHello 함수 교체 예제, 한국어 문서, 빈 디렉터리의 오프라인 빌드·시험·분석이 근거입니다. |

감사에서 보완한 실제 누락은 수신 소켓 준비 비용, 공개 계약의 묶음 전환 순서 설명, 기본 레코드보다 큰 인증서 처리와 응용 단계의 조각 범위입니다. 변경 이유는 [설계 결정](DECISIONS.md)에 기록했습니다.

## 환경과 빌드 출처

환경은 x86_64 WSL2, 커널 `6.18.58.1-microsoft-standard-WSL2`, GCC 15.2.0, CMake 4.2.3, Ninja 1.13.2, Python 3.14.4입니다. AVX2 실행 분기를 확인한 장비입니다. 기본 빌드는 구현체 8개에서 클라이언트·서버 16개 실행 파일을 생성합니다.

| 의존성 | 고정 원본 |
|---|---|
| OpenSSL | 3.5.4 배포본, SHA-256은 dependencies.py와 manifest에 기록 |
| Mbed TLS | 3.6.4 배포본, SHA-256은 dependencies.py와 manifest에 기록 |
| wolfSSL·ML-KEM | `decea12e223869c8f8f3ab5a53dc90b69f436eb2` |
| BiTHaC | `68ad825a37ef72cc1db4a67eb6d13275cc61f8aa` |
| nlohmann JSON | 3.11.3, 포함한 헤더·MIT 라이선스 해시 기록 |

[최종 빌드 manifest](../../artifacts/build-history/2026-11-16/build-message-final/source/build-manifest.json)는 공개 헤더·코어·구현체·패치·도구·시험·포함한 JSON 헤더의 해시, 컴파일 명령과 정적 라이브러리·바이너리의 출처를 보존합니다. 원본 TLS 소스를 수정한 기존 작업 트리 대신 고정 배포본과 git 객체에서 다시 추출했습니다.

## CTest의 검증 범위

소스 빌드와 시험 빌드는 각각 보존 디렉터리의 `build-message-final/source`와 `build-message-final/tests`입니다. [CTest 로그](../../artifacts/build-history/2026-11-16/build-message-final/ctest.log)와 각 시험의 `tests/evidence/*/verification.json`을 함께 읽습니다.

| 시험 | 확인하는 내용 |
|---|---|
| deterministic-core | 네 시나리오·두 레코드 정책·두 송신 정책의 16조건, 키 전환과 단계 순서, 버퍼보다 적게 생산·소비하는 큰 메시지 조각 진행, 부분 I/O에서 조립·암호화 재실행 방지, Finished+Ping 배치, 상세 비용 구간의 비중첩, 메시지 전체를 덮는 조각 범위, SHA-256, 요청 할당 계수 |
| report-contract | 큰 정수 시각의 차이, 미수집과 실제 0, StQ 분수 가중치, 공유 레코드의 비용 한 번 기록, 수신 소켓 준비를 포함한 첫 사용과 필수 사건 누락의 null 처리, 준비를 재사용에 복제하지 않음, 구형 계약 거절 |
| tls-matrix | 세 라이브러리의 3×3 동종·교차 연결 × 네 시나리오 × 두 인증 방식 × 두 계측 깊이 × 두 레코드 정책 × 두 송신 정책, 총 576조건 |
| tls-research | ML-KEM 두 구현·BiTHaC 두 구현 × 네 시나리오 × 두 인증 방식 × 두 계측 깊이의 64실행, 각각 같은 컨텍스트의 세 연결; ML-KEM C/AVX2 양방향 연결; BiTHaC 캐시 켬/끔 교차 8조건의 네 연결 |
| tls-external | 수정하지 않은 Python ssl의 시스템 OpenSSL 엔드포인트와 세 구현체 × 양쪽 역할 × 두 인증 방식의 12조건 |
| lookup-observations | 합성 객체 원격 조회와 고정 저장본, 양쪽 엔드포인트의 검증·삽입 후 실제 TLS, 준비 연결 하나와 측정 연결 둘, 할당·PMU의 가용 상태와 컨텍스트 비용 처리 |

`tls-matrix`는 추가로 ClientHello 한 함수 교체 예제 1쌍, 큰 인증서·응용 데이터의 교차 연결 6쌍, 큰 인증서로 실행하는 연구 구현 4쌍과 역할에 필요한 자격 증명만 둔 실행 3쌍을 확인합니다. 큰 인증서는 32,768바이트 확장과 체인을 포함하며 Certificate 메시지는 약 34KB입니다. 기본 16KB와 127바이트 레코드 양쪽에서 인증서를 분할합니다. 응용 요청·응답은 각각 62,003·64,007바이트이며 작은 레코드 시험의 I/O 호출 상한은 257바이트입니다. 송신 원본·수신 원본, 보호 입력·인증 복호화 출력을 바이트 단위로 대조합니다. ML-KEM·BiTHaC 네 구현에서는 큰 인증서로 컨텍스트당 세 연결을 완료합니다. 별도의 [집중 검증](../../results/message-large-certificate-fixed/verification.json)도 보존했습니다.

외부 상호운용 시험은 인증서 기반 TLS 1.3, P-256과 응용 데이터 교환을 사용합니다. 외부 서버의 세션 티켓 발급을 설정으로 끕니다. 외부 라이브러리 코드를 패치하지 않습니다. 결정적 시험의 가짜 구현 성공을 실제 TLS 성공으로 집계하지 않습니다.

## 연구 기능의 실행 증거

ML-KEM은 실제 키 생성·캡슐화·역캡슐화의 완료 수와 native 내부 최적화 분기 수를 연결 결과에 보존합니다. [오브젝트 비교](../../artifacts/build-history/2026-11-16/build-message-final/mlkem-objects.json)는 디버그 정보만 제거했을 때 C/AVX2 빌드의 코드·데이터 차이가 `wc_mlkem.c`와 `wc_mlkem_poly.c` 두 번역 단위에만 있음을 검사합니다. 최적화 분기 수를 KEM 호출 수로 바꾸지 않습니다.

BiTHaC는 첫 연결의 빈 캐시와 뒤 연결의 실제 CI·SSC 사용을 구별합니다. 캐시를 끈 상대와 반복 연결할 때 발견한 기존 항목의 잠금 반환 누락도 수정했고, 이를 양방향 회귀 시험으로 포함했습니다. 캐시를 지원하지 않는 상대와는 전체 인증이 계속 성공하면서 기법 사용 값은 0이어야 합니다. 캐시 켬/끔은 같은 원본과 경계 패치를 공유합니다.

MockCA 시험 객체는 16,384바이트입니다. 서비스의 두 요청에 TLS 실행과 같은 run_id 및 client/server 요청 역할이 남으며, 고정 저장본 경로에서는 추가 서비스 요청이 발생하지 않습니다. TLS 인증서와 합성 조회 객체는 별개입니다. 엔드포인트의 조회·검증·삽입과 서비스 자체의 준비·처리 비용을 서로 더하지 않습니다.

## 네트워크와 CPU 표본

최종 외부 관측 자료는 [results/message-final](../../results/message-final)에 있습니다. 네트워크 실행은 Mbed TLS 클라이언트와 wolfSSL 서버, 상호 인증, `finished-ping`, 컨텍스트당 두 연결, 방향별 64,000바이트 응용 데이터입니다. 별도 합성 객체 서비스도 함께 실행합니다.

| 관측 | 실제 결과 |
|---|---|
| netem·경로 | 클라이언트→서버 5 ms·1 Mbit/s, 반대 방향 7 ms·2 Mbit/s, 양쪽 손실 설정 5%, 초기 cwnd 4·5; 적용 후 qdisc·경로·MTU·offload를 다시 조회 |
| 패킷·스트림 | 양쪽 두 연결 모두 송신 스트림 전체의 연속 바이트 관측, 원본 바이트 불일치 0, 캡처 누락 0 |
| 커널 사건 | 지정 제거 2건, qdisc 제거 15건, tcp_retransmit_skb 11건을 별도 기록; ring buffer 누락 0 |
| 정리 | 관측기와 클라이언트·서버·MockCA·라우터 보조 프로세스 종료, 소유 FD 정리, 호스트 네트워크 전후 동일 |
| CPU 표본 | OpenSSL 양쪽 역할의 별도 40연결 실행, `cpu-clock:u` 997 Hz, 클라이언트 79개·서버 68개 주 스레드 표본, perf.data와 실행 당시 바이너리·build ID·심볼 출처 보존 |

[패킷 보고서](../../results/message-final/network/packet-report.json), [커널 원장](../../results/message-final/network/kernel-events.json), [호스트 전후 비교](../../results/message-final/network/host-network.json), [CPU 보고서](../../results/message-final/cpu/cpu-report.json)가 근거입니다. 지정 손실과 netem 확률 설정, 실제 qdisc 제거와 재전송은 같은 값이 아닙니다. 이 횟수는 해당 실행의 관측이며 다음 실행의 고정 기대값이 아닙니다.

CPU 전체 주 스레드 표본 중 클라이언트 20개·서버 20개는 심볼 이름을 확인하지 못한 상태로 보존했습니다. 짧은 단계에서 표본이 없는 경우도 missing으로 남깁니다. 구간 밖의 JSON 출력 등은 전체 주 스레드 보기에는 나타나지만 시나리오 보기에는 포함하지 않습니다. 함수별 period 비중을 정확한 함수 시간이나 호출 횟수로 해석하지 않습니다.

## 통계와 비교 적격성

seed `20261112`로 배치 안의 실행 순서를 저장한 뒤 실행했습니다. [기본 비교](../../results/message-final/contexts/report/report.json)는 독립 프로세스 쌍 18개, [ML-KEM 비교](../../results/message-final/mlkem/report/report.json)와 [BiTHaC 비교](../../results/message-final/bithac/report/report.json)는 각각 9개입니다. 각 컨텍스트에서 연결 세 개를 실행했습니다.

연결 위치별 분포의 독립 표본 수는 3입니다. 이를 연결 수 9로 부풀리지 않습니다. 같은 상대 구현체·역할·연결 위치·배치·조건의 탐색 비교는 각각 18·6·6개이며 컨텍스트 단위 부트스트랩 1000회를 사용했습니다. 이 실행은 기능과 비교 단위를 검증한 소규모 자료이며 성능 우열의 근거로 사용하지 않습니다. 별도 CPU 수집 실행은 일반 시간의 자동 비교에서 제외합니다.

## 오프라인 재실행과 정적 검사

다음 명령은 비어 있는 작업 디렉터리와 외부 인터페이스가 없는 새 네트워크 네임스페이스에서 의존성 추출·패치·빌드부터 CTest·정적 검사·실제 실행·JSON/CSV 분석까지 수행합니다. 고정 원본 캐시와 로컬 시험 PKI는 미리 준비되어 있어야 합니다. 시험 중 다운로드하지 않습니다.

```sh
parent_ns=$(stat -Lc %i /proc/self/ns/net)
unshare --user --map-root-user --net -- python3 tests/offline_build.py \
  --work build-offline-new --parent-inode "$parent_ns"
```

[정적 검사 결과](../../artifacts/build-history/2026-11-16/build-message-final/static.json)는 C 공개 계약, 구현체의 내부 코어 헤더 사용 금지, 부품 의존의 비순환성, 전체 handshake·네트워크 API와 동적 구현체 로더 금지, Python 문법 검사와 실제 컴파일 옵션을 적용한 clang-tidy 검사 결과를 보존합니다. 일반 코어·엔드포인트는 경고를 오류로 빌드합니다. 외부 TLS 라이브러리 전체가 별도의 정형 검증을 통과했다는 의미는 아닙니다.

## 관측 한계와 보존

OpenSSL native 레코드 버퍼의 전체 inventory는 미지원이며 null입니다. 프레임워크의 예약 버퍼, 구현체의 확인 가능한 메시지·레코드·기법 캐시 저장 공간과 요청 할당 계수는 서로 다른 값입니다. 할당 관측은 정적 호출 경로의 요청 바이트이며 RSS·스택·동적 libc 내부·allocator 관리 공간은 포함하지 않습니다.

패킷·커널 사용자 공간 수집기의 경과·CPU 사용량은 원자료에 남깁니다. 커널 관측 프로그램 자체와 perf 샘플러의 분리된 CPU 부담은 not-collected이며 0으로 빼지 않습니다. PMU 지원은 실행마다 확인하고 원계수와 time_enabled/time_running을 보존합니다. WSL의 이 기능 검증으로 물리 NIC 시각, ARM, 다른 커널의 PMU 동작이나 native Linux 성능을 확인했다고 주장하지 않습니다. netem 난수 seed의 적용 검증도 미지원입니다.

과거 실험 원자료의 내용은 수정하지 않았습니다. 원자료를 함께 포함하던 구형 빌드 디렉터리는 `artifacts/build-history/2026-11-16/legacy-builds/`으로 옮겨 보존했습니다. 개발 중의 BiTHaC 수정 전 소스·출처는 `artifacts/build-history/2026-11-16/message-development/bithac-before-cachefix/`, 큰 인증서 경계 수정 전 소스·출처는 `artifacts/build-history/2026-11-16/message-development/before-large-certificate-boundary/`에 남겼습니다. 감사 중 발견한 큰 인증서 실패 원자료도 `results/message-completion-audit/large-certificate/`에 보존했습니다. 새 도구는 구형 계약을 자동 판독하거나 변환하지 않습니다.

## 2026-11-16 작업 공간 정리 뒤 확인

활성 경로를 정리한 뒤 소스 빌드, 커널 관측기 빌드, 별도 시험 빌드, CTest 6개, 정적 검사, 기본 실제 TLS 실행과 JSON·CSV 보고서 생성을 다시 확인했습니다. 모두 통과했으며 CTest 실행 시간은 68.35초입니다. 실제 세 라이브러리의 576조건, 연구 구현·외부 TLS·큰 메시지·조회 시험이 포함됩니다. 명령과 종료 코드는 [이번 검증 원장](../../artifacts/maintenance/2026-11-16/verification.json), 출력은 [CTest 로그](../../artifacts/maintenance/2026-11-16/ctest.log), [정적 검사](../../artifacts/maintenance/2026-11-16/static.json), [기본 실행 보고서](../../results/workspace-20261116/report/report.json)에 있습니다.

고정 배포본 해시, 필요한 git 커밋에서의 로컬 archive 추출, BPF 헤더 해시와 perf 실행 파일도 [오프라인 입력 확인](../../artifacts/maintenance/2026-11-16/offline-inputs.json)으로 확인했습니다. 기존 시험 PKI를 유지하면서 변경한 PKI 기본 출력은 임시 작업 디렉터리에서 [별도로 검증](../../artifacts/maintenance/2026-11-16/pki-default.json)했습니다. 이번에는 의존성 전체를 빈 디렉터리에서 다시 빌드하거나 netem·CPU 표본을 새로 수집하지 않았습니다. 그 기능의 실제 증거는 위 2026-11-13 보존 자료입니다.
