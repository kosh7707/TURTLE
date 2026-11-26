# TURTLE

Linux에서 **내 TLS 1.3 구현의 클라이언트 또는 서버를 계측**합니다. TLS 소스와 두 제출 파일을 주면 TURTLE이 양쪽 실행 파일을 빌드합니다. 양쪽 중 지정한 역할만 계측합니다. 이미 빌드한 앱에 계측을 붙이려면 [별도 SDK 가이드](docs/sdk-guide.ko.md)를 보세요.

> 기존 체크아웃을 업데이트한다면 먼저 [무시되던 두 제출 파일 백업](implementations/README.md#기존-작업-트리를-업데이트한다면)을 확인하세요.

## 제출 구현으로 첫 실행

**준비:** Linux, C 컴파일러와 C++20 컴파일러, CMake 3.20+, Make 또는 Ninja, `pkg-config`, GNU coreutils/binutils, `flock`. 자동 테스트 인증서에는 `openssl` **명령**이 필요합니다. 예시로 쓸 OpenSSL **소스**의 빌드에는 Perl과 Make도 필요합니다. 소스 아카이브를 풀 때는 `tar`를 사용합니다. TURTLE 기본 빌드와 CSV 읽기에는 외부 JSON 라이브러리·`jq`·시스템 OpenSSL 개발 헤더가 필요 없습니다. 다른 TLS 구현의 빌드 의존성은 [예시 표](docs/examples/submissions/README.md)에서 확인하세요.

1. [예시 표의 검증된 OpenSSL 소스](docs/examples/submissions/README.md)에 맞춰 원본을 `implementations/openssl/`에 둡니다. 아래는 **새 슬롯**에만 예시를 선택합니다. 수정한 파일은 덮어쓰지 않습니다. 직접 제출할 때는 예시 선택 대신 [두 시작 파일](implementations/README.md)을 편집합니다.
2. 저장소 루트에서 아래를 실행합니다. S0은 앱 데이터 없이 TLS 핸드셰이크만 확인합니다.

   ```sh
   work=$(mktemp -d)
   tools/init-submission-example.sh openssl &&
     ./bench.sh --build-only --out "$work/build" &&
     ./bench.sh --run-from "$work/build" --scenario S0 --role client \
       --auth server --warmups 0 --repetitions 1 --out "$work/s0"
   ```

3. 케이스 판정과 연결별 시간·사이클을 읽습니다. 마지막 줄은 상태·수치처럼 쉼표가 없는 정해진 앞 열만 출력합니다. 오류 이유와 로그 경로까지 볼 때는 파일 전체를 읽습니다.

   ```sh
   cat "$work/s0/cases.csv"
   cut -d, -f1-13 "$work/s0/results.csv"
   ```

   예를 들어 `cases.csv` 앞 여섯 열이 `server,S0,client,passed,1,1`이면 서버 인증 S0의 클라이언트 본 시도 1건이 검증된 것입니다.

   `purpose=sample`이 본 시도입니다. `wall_ns`는 경과 시간(ns), `cycles`는 계측 스레드의 CPU cycle이며 **빈칸은 관측 불가이지 0이 아닙니다.** `evidence_state`와 `performance_qualified`는 별도 판정입니다. `wall_status`·`pmu_status`·`qualification_reason`으로 이유를 확인하세요. 실행 오류는 같은 행의 `client_stderr`·`server_stderr` 파일을, 빌드 오류는 `"$work/build/build/native.log"`를 먼저 봅니다. [각 열과 판정의 의미](docs/submission.md#results).
4. 같은 빌드에서 **S3(요청→응답)**을 새 결과 폴더로 실행합니다. 기존 결과나 TLS 빌드는 바뀌지 않습니다. 장기 보존할 실험은 처음부터 영구 경로에 만들고, 재사용할 빌드 폴더는 옮기지 않습니다.

   ```sh
   ./bench.sh --run-from "$work/build" --scenario S3 --role client \
     --auth server --tcp-nodelay on --warmups 0 --repetitions 1 --out "$work/s3"
   cat "$work/s3/cases.csv"
   ```

`--role both`는 역할마다 다른 연결을 실행하고, `--auth mtls`는 상호 인증을 선택합니다. `--tcp-nodelay`의 기본값은 양쪽에 `on`이며 `off`와는 실험 조건이 다릅니다. 예열과 본 시도는 각각 새 프로세스·새 연결입니다. 결과 폴더를 생략하면 `~/.local/share/turtle/runs/` 아래 새 위치를 출력합니다. `TURTLE_OUTPUT_DIR`과 `TURTLE_BUILD_DIR`로 기본 결과·프레임워크 캐시 위치를 바꿀 수 있습니다.

- [직접 포팅·결과 읽기](docs/submission.md) · [빌드 및 재사용 계약](docs/build-contract.ko.md) · [S0–S4 시나리오](docs/endpoint.md#tasks)
- 시스템 OpenSSL 개발 패키지를 사용하는 참조 피어는 기본 CMake 빌드에서 제외합니다. 내 소스 대신 참조 쌍을 실행하는 `./bench.sh --pair`가 필요할 때만 사용하세요.
