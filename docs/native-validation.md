# 네이티브 TLS 검증: 실행과 판정

**평문을 주고받았는가**와 **요청한 TLS 성능 표본을 얻었는가**를 따로 검증한다. 다음 결과는 x86-64 Linux 한 환경에서 얻은 인수 시험 기록이다. 반복 2회는 판정을 재현하기 위한 것이지 구현체의 성능 순위를 추정하기 위한 것이 아니다.

## 같은 시험 실행하기

저장소 루트에서 실행한다. [빌드 요건](../README.md)에 더해 Ninja, jq, pkg-config, GnuTLS 개발 파일이 필요하다. 배포판의 GnuTLS 명령행 도구를 설치하거나 이미 빌드된 `gnutls-cli`가 있는 디렉터리를 PATH에 둔다. GnuTLS는 여기서 **독립 시험 대상**이지 TURTLE의 빌드 의존성이 아니다.

~~~sh
set -eu
cli=$(command -v gnutls-cli)
pkg-config --modversion gnutls
mkdir -p outputs
w=$(mktemp -d "$PWD/outputs/validation.XXXXXX")
cmake -S . -B "$w/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF -DTURTLE_BUILD_REFERENCE=ON
cmake --build "$w/build" --parallel 3
cmake --install "$w/build" --prefix "$w/install"
tests/native-matrix.sh "$w/build" "$cli" "$w/matrix"
"$w/install/bin/turtle" analyze "$w/matrix/observed-client-mtls-S3"
~~~

[행렬 시험](../tests/native-matrix.sh)은 코어·SDK·기본 피어를 설치하고 해시를 고정한 **뒤**, 동일한 GnuTLS 앱 소스를 관찰 SDK 연결 유무로 각각 빌드한다. 배포판의 CLI는 재빌드하지 않는다. `$w/matrix/matrix.jsonl`에는 구성별 결과, 각 실행 디렉터리에는 프로필에 대응하는 시행 원자료와 재분석 가능한 `manifest.json`이 남는다. 재현에 필요한 버전과 해시는 `stock-version`, `gnutls-library-version`, `frozen.sha256`, `apps.sha256`에 있다. 결과를 보관하고 다음 검증에는 **새 디렉터리**를 쓴다.

## 실제 판정

아래 값은 **유효한 본 시행 수 / 실시한 본 시행 수**다. GnuTLS 3.8.12 기반의 독립 앱 하나를 역할별로 실행하고 생략한 상대에는 기본 OpenSSL 피어를 썼다. S2/S4의 선송신 능력 시험은 분모에 포함하지 않았다.

| 측정 대상 | 인증 | S0 핸드셰이크 | S1 요청 | S2 선송신 | S3 요청·응답 | S4 선송신+요청·응답 |
|---|---|---:|---:|---:|---:|---:|
| 클라이언트 | 서버 인증 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 |
| 클라이언트 | mTLS | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 |
| 서버 | 서버 인증 | 2/2 | 2/2 | 0/2 | 2/2 | 0/2 |
| 서버 | mTLS | 2/2 | 2/2 | 0/2 | 2/2 | 0/2 |

**32/40 유효.** 제외한 8회도 올바른 평문을 교환했다. 그러나 이 서버 앱은 로컬 핸드셰이크 성공 반환 **뒤에** 안내를 썼다. 따라서 S2/S4가 요구하는 선송신은 아니었다. 반면 수정하지 않은 `gnutls-cli` 클라이언트의 **0/20**은 TLS 오류가 아니라 대상의 TLS 호출 시각과 스레드 PMU 증거가 없기 때문이다. 별도 S3 대조에서 계측 앱을 상대편으로도 명시하면 클라이언트 측정(mTLS)과 서버 측정(서버 인증) 합계 **4/4**가 유효했다. 기대 서버 이름을 틀리게 준 CLI 대조는 교환 자체가 실패해 **0/2**였다.

유효 표본에서는 같은 측정 스레드의 실제 시작·종료 사건으로 경과 시간과 cycles·instructions 원누계 차를 재계산할 수 있다. 별도의 `perf` 실행 파일은 이 계수에 필요하지 않지만, 커널이 하드웨어 계수를 허용해야 한다. 보드나 권한이 다르면 기대 개수에 못 미칠 수 있다. 권한을 올리거나 추정값으로 바꾸지 않는다. 이 시험은 물리 ARM 보드에서 실행하지 않았다.

## 레코드 경계와 TCP 도달은 다른 증거다

위 32개 유효 표본에서는 측정 대상의 실제 송수신 호출에 **CH, SH, 서버 보호 묶음, 클라이언트 보호 묶음**의 경계를 대응시켰다. 서버 인증의 서버 묶음은 논리적으로 EE·SC·SCV·SF를, 클라이언트 묶음은 CF를 포함한다. mTLS에서는 각 방향에 인증 메시지가 추가된다. 묶음은 여러 레코드에 걸칠 수 있으며 **내부 메시지마다 시각을 부여하지 않는다**. 로컬 TLS 쓰기 수락·읽기 반환과 TCP ACK도 같은 사건이 아니다.

선택 시험은 libpcap 개발 파일로 빌드한 뒤, 네트워크·마운트 네임스페이스와 netem을 쓸 수 있는 Linux에서 실행한다. 위 행렬에서 만든 앱을 그대로 사용한다.

~~~sh
tests/native-network.sh "$w/install/bin/turtle" "$w/matrix/chat" "$w/network"
~~~

[이 시험의 프로필](../tests/native-network.sh)은 mTLS S4에 `network: "netem"`, `netem.additional_rtt_ms: 16`, 방향별 `loss_pct: 20`(클라이언트→서버)과 `0`(역방향), `measurement.capture: true`, `required_metrics: ["capture"]`를 지정한다. 실행 전후 실제 qdisc에서 방향별 **8 ms** 설정을 대조한다. 20%는 설정한 손실 확률이지 그 시행에서 정확히 20%가 유실됐다는 뜻이 아니다. 특정 패킷의 누적 ACK가 안내 레코드의 마지막 바이트를 덮을 때만 도달 순서를 판정한다. 근거가 없으면 미확인이다. 망 설정 권한이 없으면 요청한 망을 루프백으로 바꿔 합격시키지 않는다.
