# TURTLE의 구현 결정

## 이번 작업의 기준

최신 사용자 요청에 따라 기능 명세와 작업 지시서는 목표를 이해하는 참고 자료로 사용합니다. 정상 경로 TLS 1.3 벤치마크를 실제로 실행하고, 이후 연구자가 직접 수정할 수 있는 코드를 인계하는 것이 목표입니다. 강건성이나 공격 시험은 만들지 않습니다.

## 객체 소유와 제어의 분리

SUPERCOP에서는 구현자 계약과 공통 측정을 분리하는 구조를 참고합니다. Spring에서는 흐름을 프레임워크가 관리하고 필요한 서비스를 명시적으로 전달하는 생각을 참고합니다. Spring을 의존성으로 가져오거나 싱글톤 수명 모델을 복제하지 않습니다. 역할별 실행 객체가 구현체 컨텍스트, 통신, 계측, 기록의 수명을 소유합니다.

## 지원하지 않는 계측

권한이나 장비가 없어 카운터 또는 하드웨어 시각을 얻지 못하면 값과 이유를 별도로 기록합니다. 0으로 대체하거나 더 높은 관측 수준을 주장하지 않습니다. 라이브러리 경계 구간과 커널의 관측은 서로 다른 의미로 남깁니다.

## 무효 표본과 범위

무효 실행은 이유와 함께 보존하며, 정상 표본 수를 채우려고 자동 재시도하지 않습니다. 기본 실행은 정상 경로만 다룹니다. 부분 송수신과 읽기·쓰기 대기는 정상적인 비차단 입출력의 일부이므로 지원합니다. 공격이나 비정상 프로토콜에 대한 강건성 시나리오는 만들지 않습니다.

## 기록과 분석

원자료를 기준으로 별도 오프라인 도구가 해석과 통계를 계산합니다. 암호문 바이트 범위와 평문 메시지 범위를 일대일이라고 가정하지 않습니다. 여러 메시지가 한 구간에서 처리되면 묶음으로 남깁니다. 측정 자체의 비용은 원자료와 함께 공개하며 보정된 값을 실제 정답으로 취급하지 않습니다.

## JSON 원자료 의존성

JSON 형식의 원자료와 프로필을 정확하게 읽고 쓰기 위해 nlohmann/json 3.11.3의 단일 헤더와 MIT 라이선스를 포함합니다. 직접 JSON 파서를 만드는 것보다 검증과 유지보수 범위를 줄이기 위한 선택입니다. 이 코드는 측정 경로에서 호출하지 않습니다. 원본은 공식 저장소의 `v3.11.3` 태그이며 헤더의 SHA-256은 `9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6`입니다.

## 구현체 모듈과 상태

클라이언트와 서버에 서로 다른 라이브러리를 연결할 수 있도록 구현체마다 공유 모듈을 만듭니다. 역할 프로세스가 해당 모듈을 읽고 함수표를 값으로 받으며, 컨텍스트를 명시적으로 생성·파괴합니다. 지휘 프로세스는 라이브러리를 초기화하지 않습니다. 사용자 인자가 없는 외부 할당 콜백에만 어댑터 내부의 비소유 스레드별 연결 포인터를 제한적으로 허용하며 소유 계측기는 역할 런타임에 둡니다.

## 프로필 식별

프로필과 환경은 전체 내용을 원자료에 보존하고 안정적인 FNV-1a 64비트 지문을 함께 붙입니다. 이 지문은 편리한 식별용이며 무결성이나 보안성을 주장하지 않습니다. 지문을 계산하려고 지휘 프로세스에서 OpenSSL을 초기화하면 자식의 할당 함수 설치에 영향을 줄 수 있으므로, 코어에서는 libcrypto를 사용하지 않습니다.

## 이번 구현에서 정한 기본값

`TCP_NODELAY`는 켜고 요청 소켓 버퍼 크기는 각각 65,536바이트로 둡니다. 이는 요청값이며 Linux가 내부에서 적용하는 실제 크기와 동일하다고 주장하지 않습니다. 호환용 ChangeCipherSpec은 공통 프로필에서 켭니다. 기본 측정은 1,000번, 준비 연결은 0번이며 캐시를 밀어내는 배열 훑기는 넣지 않았습니다. 이 선택이 모든 장비에서 최적이라는 의미는 아닙니다.

## 메모리와 스택의 범위

요청 힙 바이트의 현재값·구간 최고값과 스택 최고 사용량은 다른 계측입니다. 스택을 얻으려고 실행 중인 스택을 덮는 코드는 넣지 않았습니다. 스택은 미지원으로 둡니다. 힙도 실제 할당기의 머리글·정렬 여유·재할당 내부 순간 복제를 포함하지 않는다는 한계를 공개합니다.

## 원래 명세와 달라진 관측 범위

기본 통신은 콜백을 통한 실제 TCP입니다. 커널 수신 시각은 `SO_TIMESTAMPNS`로 얻고 원래 시계를 보존합니다. 송신 오류 대기열·NIC 시각·eBPF·패킷 캡처는 구현했다고 표시하지 않습니다. 네이티브 소켓 경로는 `library-only`이며 시스템 호출 경계라고 부르지 않습니다. 키 로그와 원자료 스트림의 해독은 실제 AES-128-GCM/SHA-256으로 확인하고, 미지원 암호 방식은 경계 관측과 분리하여 설명합니다.

## 식별과 빌드 재현

원자료의 프로필 지문에는 실제 읽은 인증서 입력의 크기와 내용 지문도 포함합니다. 개인키 내용을 JSON에 넣지 않습니다. 프로필에는 경로도 남으므로 설치 위치가 바뀌면 지문이 달라질 수 있습니다. 지문은 보안 해시가 아닙니다. 프레임워크의 컴파일러·빌드 형식·옵션·소스 리비전은 생성된 빌드 정보와 환경 지문에 포함하며, 실험 스크립트는 컴파일 명령과 CMake 설정도 복사합니다. 수정 중인 트리는 `dirty`로 구별합니다.

## 원래 문서의 보존

최초 README는 `docs/design-history.md`에 보존했습니다. 현재 실행 명령과 지원 범위는 최상위 README, 진행 상태와 확장 목표는 `docs/PROGRESS.md`가 기준입니다. 원래 작업 순서의 모든 항목을 구현했다고 쓰지 않습니다.

## 자동 비교의 최소 조건

서로 다른 상대 엔드포인트를 한 분포에 섞지 않습니다. 같은 표본 폴더의 반대 역할 머리글을 확인하고 실제 CPU·라이브러리 판·빌드 옵션을 그룹 조건으로 사용합니다. 상대 정보를 확인할 수 없는 단일 역할 입력도 원자료 요약은 가능하지만 자동 비교에서는 제외합니다. 묶음 번호 집합이 다르면 자동 비교를 만들지 않습니다. 이 조건을 통과해도 통계적 비교 후보일 뿐, 구현의 의미나 보안 성질이 같다는 증명은 아닙니다.

## TCP 설정의 요청값과 실제값

2026년 10월 15일, 최초 작업 순서의 M1을 보완하면서 설정 성공 반환만으로 TCP 준비가 끝났다고 보던 경로를 바꿨습니다. TLS를 시작하기 전에 비차단 플래그와 `TCP_NODELAY`, 송수신 버퍼, 수신 시각 옵션을 다시 읽습니다. 필수 설정을 확인하지 못하면 실행을 중단합니다. 요청한 수신 시각 기능을 사용할 수 없는 경우에는 기존처럼 미지원 사실을 남깁니다.

Linux는 송수신 버퍼에 내부 관리 공간과 하한·상한을 적용하므로 요청 바이트와 조회 바이트를 같다고 검사하지 않습니다. 이 동작은 [Linux socket(7) 매뉴얼](https://man7.org/linux/man-pages/man7/socket.7.html)의 `SO_SNDBUF`와 `SO_RCVBUF` 설명을 따릅니다. 요청값은 프로필에, 조회값은 각 연결의 `socket`에 보존합니다. 조회값이 다른 양쪽 엔드포인트의 표본은 같은 보고 그룹에 섞지 않습니다.

## 반복 실행의 컨텍스트 입력 고정

M3의 컨텍스트는 TLS 세션 재개가 아니라 구현체가 선언한 연결 사이 상태입니다. 지휘 프로세스가 `--context` 폴더의 클라이언트·서버 저장본을 실행 시작 때 한 번 읽고, 각 새 역할 프로세스에 같은 바이트를 전달합니다. 표본이 새로 저장한 결과를 다음 반복의 입력으로 덮어쓰지 않습니다. 준비 연결은 같은 프로세스 안의 별도 기능입니다.

저장본 내용은 코어가 해석하지 않습니다. 기존 FNV-1a 식별 함수로 입력의 크기와 지문을 기록하고 양쪽 역할의 입력을 보고 조건에 포함합니다. 지문은 보안 해시나 상태의 의미가 같다는 증명이 아닙니다. 비어 있지 않은 입력인데 지문이 없는 예전 원자료는 요약하되 자동 비교하지 않습니다. 모의 구현의 8바이트 핸드셰이크 횟수로 저장·복원을 시험하며, 세 실제 TLS 어댑터에 가짜 상태나 세션 재개를 추가하지 않습니다.

## 여러 측정 연결을 가진 시나리오

M1의 연결 수 입력은 준비 연결 수와 구별합니다. `--connections`의 기본값 1은 기존 동작을 보존하고, 2 이상이면 같은 엔드포인트 프로세스와 컨텍스트에서 순서대로 측정합니다. TCP와 기록 공간은 모든 연결에 대해 격리 전에 준비합니다. 보고서는 연결 위치별 분포를 만들며, 같은 프로세스의 여러 연결을 독립 반복으로 늘려 세지 않습니다. 전체 연결 수·준비 연결 수·연결 위치가 다른 결과는 자동 비교하지 않습니다.

## 암호군을 하나로 고정

2026년 10월 15일 사용자 결정에 따라 비교 암호군은 `TLS_AES_128_GCM_SHA256`만 허용합니다. 다른 암호군 해독·협상 지원은 남은 구현 항목이 아닙니다. 명령행·프로필과 직접 런타임 호출에서 다른 값이나 후보 목록을 거절하며, 단독으로 쓰는 OpenSSL 어댑터도 같은 제한을 적용합니다. 기존 원자료 필드와 공개 구조는 유지합니다.

암호군 고정이 키 교환 그룹이나 인증서 서명 방식까지 고정한다는 뜻은 아닙니다. TLS 1.3의 이 선택들은 별개입니다([RFC 8446, 4.1.1절](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.1)). 따라서 인증서 체인·서명 방식 실험은 이 결정과 양립하며, 세 라이브러리의 공통 지원 범위는 별도로 지킵니다.

## 합성 조회와 stock TLS를 분리

2026년 10월 15일, 첫 모의 CA 범위는 클라이언트의 선행 인증서 객체 조회 뒤 표준 TLS를 실행하는 `synthetic-lookup-plus-standard-tls`로 고정했습니다. 조회 응답은 기준 원본과 byte-for-byte 비교하고 캐시에 삽입하여 실제로 소비하지만, 어댑터의 인증서 입력은 바꾸지 않습니다. 이 선택은 기존 adapter v1과 정상 TLS 의미를 보존하고 CA·조회 비용을 독립적으로 관측하기 위한 것입니다.

범용 adapter v2 다중 소켓 API, 핸드셰이크 도중 조회, 서버 조회자, 누적 캐시, 인증서 압축은 구체 기법이 필요해질 때까지 도입하지 않습니다. 지금 결과를 인증서 축소나 stock TLS 최적화로 부르지 않습니다.

## 캐시 초기 상태와 객체 수명

공개 PEM 원본은 parent가 실행 시작 때 한 번 읽어 불변 기준 snapshot으로 보유합니다. 조회 캐시는 연결마다 같은 empty/fixed snapshot으로 직접 복원하며 이전 연결의 변경을 누적하지 않습니다. 객체 ID는 FNV-1a 식별값이고 실제 동일성은 크기와 바이트로 판단합니다. cache logical bytes, 선확보 capacity, reference bytes, framework reserved bytes와 allocator heap은 중복 합산하지 않습니다.

## 모의 CA의 독립 계측

모의 CA를 TLS `Role`에 추가하거나 TLS Declaration/Verification을 가짜로 채우지 않습니다. 별도 참여자·프로세스·서비스 schema와 heap tracker를 사용하며, CA process 경과·CPU·입출력·대기를 독립적으로 보고합니다. lookup의 시계·perf 관측은 클라이언트 TLS Meter를 재사용해 엔드포인트당 perf 그룹을 하나로 유지합니다.

## 조회용 rootless 소유 topology와 netem 해석

합성 조회에서는 host 네트워크를 바꾸는 단순 실행 대신 새 user/network namespace 안에서 client/server/ca/router 네 data namespace와 네 veth 링크를 소유합니다. `/run/netns`, host route, host interface와 host qdisc는 건드리지 않습니다. 수신자 직전 router egress의 네 방향 qdisc를 attempt마다 삭제·재생성하며, MTU와 TSO/GSO/GRO 실제 readback이 요청과 맞아야 합니다. 조회가 꺼진 topology의 후속 결정은 아래에 별도로 기록합니다.

netem loss는 skb 단위 정책·집계입니다. qdisc drop, socket TCP retransmission, 조회 경과를 같은 단위나 순수 RTT로 취급하지 않습니다. 조건 그룹에는 topology·정책·MTU·offload 같은 안정 입력과 실제 적용 조건만 넣고 PID/FD/port/handle/timestamp 및 drop/retrans/outcome은 넣지 않습니다.

## attempt 원장과 최초 원인 고정

`samples`를 attempt 분모로 유지하고 별도 attempts 옵션을 만들지 않습니다. 기본 `fail-fast`와 명시적 `fixed-attempts`를 구별하며 실패를 자동 재시도로 채우지 않습니다. parent 원장이 child 파일보다 먼저 started 상태를 기록합니다.

deadline은 attempt 전체의 하나의 absolute 시각입니다. 최초 terminal 원인이 deadline 초과면 timeout, 그 전에 확인한 오류면 error입니다. 뒤의 flush·kill은 최초 원인을 바꾸지 않습니다. abort 시 한 번 정한 기본 500ms flush grace를 연장하지 않으며, 그 뒤 SIGKILL과 별도 250ms OS reap 상한을 적용합니다. 회수 완료를 증명하지 못하면 다음 attempt를 시작하지 않습니다.

## 인증서 유효 기간을 한 번 계산

이전 PKI 반복 시험의 `certificate is not yet valid`는 발급 도중 시계가 뒤로 움직이면 인증서마다 서로 다른 시작 시각을 얻던 방식에서 발생했습니다. 정상 인증서 검증을 끄지 않고, `make-pki.sh`가 발급 시작 때 UTC 시각을 한 번 읽어 root·intermediate·leaf 모두에 같은 유효 기간을 적용하도록 바꿨습니다. 시작은 그 시각보다 300초 앞, 끝은 발급 시각보다 3,650일 뒤입니다.

임의 검증 시각 주입이나 검증 비활성화는 선택하지 않았습니다. OpenSSL 3.0에서도 명시적 시작·종료 시각을 지원하도록 `openssl ca`를 사용하고, 정상 `openssl verify`는 유지합니다. ECDSA·RSA2048·Ed25519 잎과 체인 길이 1~3의 9조합을 각 두 번 system OpenSSL 3.0과 고정 OpenSSL 3.5에서 확인했습니다. 별도 shim은 host 시계를 역행시키지 않고 발급 과정의 `date` 출력만 실제 검증 시각보다 240초 앞당겼으며, 그렇게 발급한 인증서도 실제 시각의 정상 검증을 통과했습니다.

## 정적 검사 실패를 보존하고 수정

Mock CA 통합 뒤 첫 `static-first.log`는 cppcheck의 `passedByValue` 2건과 clang analyzer의 dead store 2건 때문에 실패했습니다. 이를 성공 기록으로 바꾸지 않습니다. 불필요한 값 복사와 사용되지 않는 상태 저장을 제거한 뒤 `pre-loss-static.log`에서 21개 생산 번역 단위의 cppcheck·clang-tidy가 통과했습니다.

bounded cleanup의 운영 경로에 범용 오류 주입 옵션을 넣지 않았습니다. 소유 PID만 kill/reap하는 내부 계약과 테스트 전용 wrapper로 경계를 시험합니다. 실제 timeout 세 attempt는 cleanup grace 뒤 SIGKILL과 owned reap을 실행했습니다. 고정 250ms는 그 뒤 OS 회수의 최대 budget이지 관측 시간값이 아닙니다. 반면 N05 loss 64 attempts에는 강제 종료가 없었습니다. 회수 syscall의 합성 EIO처럼 완료를 증명할 수 없는 분기는 통제된 wrapper 시험에만 둡니다.

## 네트워크 비교 적격성은 fail closed

network attempt가 성공 상태라는 사실만으로 자동 비교에 넣지 않습니다. setup/scenario/cleanup begin/end의 정확히 여섯 observation 참조, 같은 attempt의 실제 observation, host network unchanged와 owned cleanup이 모두 있어야 합니다. 누락·중복·불일치·손상된 provenance는 비교 부적격입니다.

새 attempt 원장이 존재하지만 손상됐으면 `director.txt`나 자식 파일로 성공을 추정하지 않습니다. 과거 fallback은 원장이 전혀 없는 옛 TLS 자료에만 제한합니다. loopback metric은 설명용 분포에 보존할 수 있지만 network 비교 identity를 가진 것으로 간주하지 않습니다.

## 조회 여부에 따라 topology 자원을 줄임

`scripts/netem-study.py run`은 실행 프로필의 `lookup.enabled`를 topology 선택의 기준으로 사용합니다. 조회가 켜지면 기존 client/server/ca/router 네 namespace·네 링크·네 방향을 그대로 사용합니다. 조회가 꺼지면 client/server/router 세 namespace·두 링크·두 TLS 방향만 만들고 C++에는 client/server namespace FD만 전달합니다. 비활성 CA 자원을 만들어 놓고 결과에서만 숨기는 방식은 선택하지 않았습니다.

조회가 꺼진 설정에는 객체·캐시·snapshot 경로가 없어도 됩니다. attempt 참여자와 필수 원자료도 두 TLS 역할뿐입니다. `verify`의 기존 M13·M14 고정 묶음은 조회 경로 전용으로 유지하고, 순수 TLS는 일반 `run` 명령과 별도 통합 시험으로 확인합니다. 이 결정 때문에 고정 N05 64회 조건을 확장하거나 다시 실행하지 않습니다.

namespace helper 준비에는 고정 sleep을 사용하지 않습니다. helper가 `unshare`와 namespace 진입을 마친 뒤 readiness pipe로 알리고, parent는 bounded 신호를 받은 뒤에만 namespace FD를 엽니다. 고정 30ms 대기는 동시 시작에서 ENODEV를 재현했으므로 거절했습니다. EOF·timeout·조기 종료는 준비 완료로 추정하지 않고 setup 실패로 처리합니다.

## 네트워크 조건 identity와 integrity 결과를 분리

일반 TLS 보고 그룹에도 사용자가 요청한 net-profile과 provenance에서 확인한 실제 topology·활성 경로·qdisc·MTU·offload 조건을 함께 넣습니다. 준비 연결과 측정 연결 양쪽의 실제 소켓 설정도 조건입니다. 반면 metric은 측정 연결에서만 수집합니다.

host unchanged, phase observation, helper/observer 회수 같은 실행 integrity 결과와 success/timeout, drop, retrans는 안정 그룹 키에 넣지 않습니다. 이 결과는 표본·run metadata와 그룹의 최상위 자동 비교 적격성으로 판정합니다. 따라서 같은 네트워크 조건의 실패를 별도 조건처럼 분리하지 않으며, integrity가 실패한 표본의 metric은 비교 분포에 넣지 않습니다.

## 수명주기에서 구체 조회 책임을 분리

공통 자식 제어 프로토콜은 `endpoint_protocol.cpp`로, 캐시·조회 wire·lookup 원자료와 모의 CA 실행은 `lookup_runtime.cpp`의 구체 `ClientLookupRuntime`으로 옮겼습니다. `lifecycle.cpp`는 표본·역할·연결의 순서와 실패 회수를 계속 소유합니다. 범용 플러그인이나 서비스 조회기를 만들지 않고 실제로 독립된 조회 책임만 분리했습니다.

## 기능 성공과 I/O 관측 가능성을 분리

OpenSSL native socket 경로에서는 TLS 라이브러리가 framework `Io`를 거치지 않습니다. 성공한 TLS와 응용 핑퐁을 framework stream·I/O·kernel receive 값 0으로 바꾸지 않고, 각 수집 통로를 이유 있는 unavailable로 기록합니다. native client의 TLS 호출 경과·스레드 CPU는 실제 호출 snapshot에서 보존하되 I/O 분해를 추정하지 않습니다. native server의 첫 성공 receive 기반 주 구간은 만들지 않으며 handshake 시작으로 대체하지 않습니다.

기능 유효성, 주 구간 availability와 I/O 분해 availability는 서로 독립입니다. native 그룹은 기존 자동 성능 비교에 넣지 않습니다. 해석기도 native 빈 stream을 성공한 0바이트 해독으로 보지 않으며, availability 필드가 없는 과거 library-only 자료만 명시적인 legacy 규칙으로 읽습니다. wolfSSL·Mbed TLS에는 native 지원을 추가하지 않았습니다.

## native/callback 외부 근거는 skb metadata로 제한

M6은 새 packet 도구나 netem 조건을 만들지 않고 기존 lookup=false zero-loss runner를 재사용합니다. 수신자 쪽 router egress의 AF_PACKET 행을 주소·TCP 4-tuple·방향으로 제한해 skb count와 payload 합을 기술하지만 두 모드의 수치 동일성을 요구하지 않습니다. 사용자 공간 observer-read timestamp, 근사 phase window, 재전송·분할 가능성을 함께 기록합니다. 이를 syscall trace, full pcap, 고유 TLS bytes, 물리 packet·wire 시각이라고 부르지 않습니다. M13·M14와 N05의 고정 범위는 바꾸지 않습니다.

## 관측자 off는 포인터 하나만 바꿈

M7은 공개 adapter ABI나 CLI 옵션을 추가하지 않고 JSON의 `measurement.channel_observer`만 사용합니다. 기본값과 과거 필드 부재는 true입니다. false이면 같은 callback transport에 전달하는 관측 함수 포인터만 null로 만들며 socket 설정·실제 버퍼·kernel timestamp 준비·호출/대기·keylog/plaintext·perf는 유지합니다. 따라서 observer-disabled를 uninstrumented 실행으로 부르지 않고 stream·I/O·kernel receive 수집만 이유 있는 unavailable로 기록합니다.

## observer 비교에는 이름 있는 공통 호출 경계를 사용

기존 server primary는 first framework receive에서 시작하므로 observer off에서 unavailable인 의미를 바꾸지 않습니다. 대신 양 역할·양 모드에 `handshake_call_begin_to_application_complete`를 별도 계산합니다. 첫 handshake 호출 시작부터 역할의 전체 최종 application 호출 완료까지이며 partial progress를 모두 확인합니다. elapsed와 thread CPU는 독립 availability를 가지며 CPU 누락을 elapsed 실패로 확대하지 않습니다.

`channel_observer`는 안정 그룹 조건이고 공통 경계 metric은 기존 primary 이름과 분리합니다. observer off나 native server에도 공통 metric이 있을 수 있지만 이를 primary로 승격하거나 기존 자동 비교에 넣지 않습니다. TLS·parent 원장·network integrity가 실패하면 공통 metric도 그룹에 수용하지 않습니다. on/off 차이는 역할별 진단 산술값일 뿐 방향·부호·크기·유의성이나 WSL 성능 결론을 합격 기준으로 두지 않습니다.

## 관측자 상태의 호환 판독을 하나로 맞춤

명시적인 `config.channel_observer=false`이거나 `observation_level=observer-disabled`이면 observer off로 판독합니다. config 필드가 없고 marker도 없으면 과거 callback 기본값인 on입니다. `library-only`, native socket, TLS stream availability나 빈 stream만 보고 observer off를 추론하지 않습니다. native I/O visibility와 channel observer 선택은 서로 다른 조건입니다.

일반 보고서와 해석기는 이미 이 규칙을 사용했습니다. lookup 보고서의 조건 identity는 이전에 config 필드의 기본값 true만 읽어 marker-only 자료를 on으로 분류했으므로 같은 판독 정책으로 맞춥니다. 현재 producer는 `channel_observer` 필드를 항상 기록하므로 G011 실제 원자료와 검증 결과는 바뀌지 않습니다. 다만 필드가 없고 `observer-disabled` marker만 있는 호환 자료를 다시 보고하면 조건 키가 이전 on에서 off로 바뀔 수 있습니다. 이는 오래된 자료를 올바른 조건 그룹에 두는 correctness 수정이며 별도의 NOOP cleanup과 섞지 않습니다.

## 여섯 phase 참조에는 관측 본문도 필요함

성공한 network attempt의 setup/scenario/cleanup begin/end ID 여섯 개가 존재한다는 사실만으로 integrity를 통과시키지 않습니다. 각 참조 행에는 비어 있지 않은 `qdiscs` 객체가 있어야 하고, trace 요청이 true이면 `packet_trace`도 존재하며 null이 아니어야 합니다. 누락·빈 qdisc, 누락·null trace는 안정 condition identity를 바꾸지 않지만 integrity와 metric 수용을 fail closed로 만듭니다. lookup과 일반 pure TLS가 같은 shared 판독 규칙을 사용합니다.

## noqueue의 null queue limit은 명시적 not-applicable

요청 qdisc와 실제 qdisc가 모두 `none`이고 실제 path kind가 `noqueue`이며 `limit_packets` 필드가 명시적으로 null인 경우에만 queue limit을 not-applicable로 받아들입니다. field 자체가 없거나 netem path의 limit가 null이면 관측 불완전으로 거절합니다. 이 구별은 보존한 N05 baseline의 실제 readback과 엄격한 누락 검사를 함께 유지하기 위한 좁은 호환 규칙입니다. runner, network 조건이나 N05 원자료는 바꾸거나 다시 실행하지 않습니다.

## 키 공유 생성은 핸드셰이크 측정 구간에 둔다

2026년 10월 15일, 세 TLS 구현의 전체 핸드셰이크를 같은 경계로 비교하기 위해 wolfSSL의 P-256 키 공유 생성을 `open()` 밖으로 옮기기로 했습니다. 컨텍스트에 허용 그룹과 선호 순서를 P-256 하나로 고정하고, 라이브러리의 지연 생성 경로를 사용합니다. 그러면 클라이언트는 ClientHello를 만들 때, 서버는 ClientHello를 받아 처리할 때 키를 생성합니다. 서버 주 구간은 첫 성공 수신에서 시작하므로 이 작업도 기존 구간 안에 들어옵니다.

`open()` 비용 전체를 주 구간에 합치는 방법은 연결 준비와 핸드셰이크를 섞으므로 선택하지 않았습니다. `wolfSSL_UseKeyShare`를 서버의 첫 `handshake_step()` 앞으로만 옮기는 방법도 수신 전에 생성이 끝나 서버 주 구간에서 빠지므로 선택하지 않았습니다. 측정 구간을 임의로 늘리지 않고 같은 프로토콜 작업이 같은 종류의 구간에서 수행되게 하는 것이 이 선택의 이유입니다.

세 어댑터는 설정 단계에서 신뢰 CA를 읽고, 해당 역할에 로컬 인증서 체인과 개인키가 있으면 함께 읽습니다. 상대 인증서 해석과 검증, ClientHello·ServerHello의 임시 키 생성은 핸드셰이크 안에서 수행됩니다. 이 설명은 라이브러리 내부 캐시가 같다거나 모든 ASN.1 작업의 위치가 같다는 뜻이 아닙니다.

원자료 형식 1은 유지하고 최상위 선택 필드 `measurement_contract_revision`으로 측정 의미를 구별합니다. 개정값 1은 이 키 생성 배치만 반영한 역사 계약입니다. 후속 D2가 I/O 반환 캡처의 귀속을 바꾼 뒤 새 원자료는 개정값 2를 씁니다. 필드가 없는 예전 원자료는 정의를 알 수 없는 자료로 계속 읽고 기존 지표·표본·분포를 보존하지만 자동 비교에서만 제외합니다. 개정값 1의 수치를 2의 의미로 소급 보정하지 않습니다.

## 레코드 귀속은 새 측정이 아닌 보고 보기이다

핸드셰이크 연산 구간의 앞·뒤에 레코드 이름을 붙이는 보기는 기존 사건 시각과 해독 결과로 보고 단계에서 만듭니다. 이 보기를 도입할 때는 원자료 생성 시점·주 측정 구간·당시 `measurement_contract_revision=1`을 바꾸지 않았습니다. 현재 생성자의 개정값 2는 후속 D2의 I/O 반환 귀속 변경 때문이지, 레코드 보고 보기 때문이 아닙니다. 서버의 ClientHello 수신 반환→Finished 송신 반환 구간도 같은 원자료에서 만드는 추가 보고 구간이며, 기존 서버 주 구간을 대체하지 않습니다.

각 연산 구간은 한 번만 저장하고 시작·끝 귀속을 각각 붙입니다. 하나의 구간이 수신 레코드 뒤에 시작하고 송신 레코드 앞에 끝나더라도 시간을 두 번 합산하지 않습니다. 여러 TLS 메시지가 하나의 레코드나 하나의 입출력 반환에 묶이면 이름 목록과 묶임 표시를 그대로 남기고 시간을 메시지별로 나누지 않습니다.

이 귀속은 라이브러리가 특정 레코드를 받은 뒤 또는 보내기 전에 언제 작업했는지를 보여 줍니다. 특정 메시지의 내재적 비용이나 순수한 라이브러리 시간을 의미하지 않습니다. 라이브러리마다 전송 묶음과 작업 스케줄이 다르므로 개별 메시지 이름의 수치를 자동 비교하지 않습니다. 같은 경계로 정의한 전체 핸드셰이크 구간 합계만 서로 비교할 수 있는 단위로 취급합니다.

## I/O 반환 캡처를 스냅샷 앞에 둔다

성공한 I/O 반환의 바이트 복사와 사건 공간 준비가 이전에는 반환 스냅샷 뒤에 있어 후속 `computation` 구간에 들었습니다. 현재는 반환 사건의 고정 공간을 예약하고, 스트림 바이트를 복사하고, `first_receive`를 고정하고, 필요한 `KernelRx` 고정 공간을 준비한 뒤 스냅샷을 한 번 읽습니다. 반환과 커널 사건은 같은 스냅샷을 쓰며 기존 순번·스트림 범위·커널 원시 시각을 보존합니다. 이 작업을 커널 입출력과 함께 프레임워크 I/O 비용으로 분류하기 위한 선택입니다.

스냅샷은 성능 카운터, 스레드 CPU, 단조 시각, 힙을 순서대로 읽는 복합 작업입니다. 스냅샷 후의 고정 공간 대입과 관측자 복귀 비용은 여전히 후속 구간에 들 수 있습니다. 교정값을 빼서 참값을 복원했다고 주장하지 않고, `computation`과 레코드 귀속 시간을 순수한 라이브러리 비용으로 부르지 않습니다. 이 변경은 측정 계약 개정값 2로 구별하며 개정값 1의 수치를 새 귀속으로 다시 해석하지 않습니다.

## 수신 정책 선언은 adapter ABI 2로 올린다

`Declaration`의 `read_ahead`와 `read_ahead_note`가 C++ 구조체 배치를 바꾸므로 어댑터 ABI를 2로 올렸습니다. 로더는 `turtle_adapter_v2`만 찾고 v1 전용 모듈을 `declaration`·`setup` 호출 전에 거절합니다. v1 호환 계층을 두면 구 구조체를 새 배치로 잘못 호출할 위험이 있으므로 만들지 않았습니다. 모든 어댑터를 새 헤더로 다시 빌드합니다.

`read_ahead=false`는 현재 TLS 레코드에 필요한 범위를 넘어 다음 레코드를 선행 수신하지 않는 정책입니다. OpenSSL은 설정과 조회값을 0으로 고정합니다. wolfSSL은 호환 필드 0을 보존하지만 실제 알고리즘은 그 필드가 아닌 고정 판의 필요 잔여량 수신 경로를 근거로 합니다. Mbed TLS는 설정 함수가 없고 같은 필요 잔여량 수신 경로를 근거로 합니다. 이 선언은 실제 TCP에서 레코드당 `recv` 횟수를 두 번으로 보장하지 않습니다.

## CPU 위상은 독점 사용 증명이 아니다

허용된 CPU만으로는 SMT 형제와 물리 자원 공유를 알 수 없으므로 sysfs의 package/core ID, `thread_siblings_list`, 온라인 상태를 별도로 기록합니다. 형제는 affinity 허용 범위 밖에 있어도 제외하지 않습니다. 목록·온라인 여부·위상을 알 수 없으면 `null`과 이유를 남기고 독립 코어로 꾸며 내지 않습니다.

같은 것으로 확인한 물리 코어에 여러 역할을 고정하는 설정은 기존처럼 거절합니다. 다른 CPU를 선택해도 온라인 또는 상태 미상 SMT 형제의 유휴 상태와 코어 전용 사용은 확인할 수 없음을 경고합니다. CPU 고정을 끄면 역할 배치 미확인으로 남깁니다. WSL의 게스트 위상을 호스트 물리 코어 전용 증거로 쓰지 않습니다.

환경 식별에는 `perf_event_paranoid`와 위상·형제 정보 같은 안정 사실을 넣지만, 동적 부하, 관측 시각, errno, 경고 문구는 넣지 않습니다. `perf_event_paranoid`는 정책 설명일 뿐 실제 카운터 설정 성공을 증명하지 않습니다.

## 성능 카운터 범위는 요청·상태·실제를 분리한다

프레임워크 설정 `perf_scope`는 기본 `user`와 명시적 `user+kernel`을 구별합니다. 어댑터 기능 선언으로 두지 않습니다. 둘 다 같은 역할 스레드의 계수이고 하이퍼바이저와 다른 스레드를 제외합니다. `user+kernel`은 전체 시스템 커널 비용을 뜻하지 않습니다.

요청 범위, `disabled|available|unsupported` 상태, 실제 범위를 독립적으로 기록합니다. 비활성과 미지원의 실제 범위 `null`은 알려진 상태이며, 필드 누락의 알 수 없음과 구별합니다. `user`의 미지원은 측정값만 미계측으로 두고 정상 TLS와 시간 측정을 계속합니다. 명시적 `user+kernel`을 적용하지 못하면 원자료·원장에 이유를 남기고 실패하며 `user`로 낮추지 않습니다. `perf=false`와 `user+kernel`은 실행 전 모순 설정으로 거절합니다.

설정 실패 단계·errno·설명은 진단으로만 남기고 그룹 조건으로 삼지 않습니다. 일반 보고와 조회 보고 모두에서 양쪽 엔드포인트의 요청·상태·실제 범위를 안정 조건으로 사용합니다. 구 원자료에 필드가 없으면 기존 지표·분포는 보존하되 자동 비교만 제외합니다. 이 추가는 원자료 형식 1과 측정 계약 개정값 2를 바꾸지 않습니다.
