# TURTLE

TURTLE은 Linux에서 TLS 1.3 핸드셰이크와 앱 데이터 교환에 걸리는 시간을 측정합니다. 같은 TLS 소스로 클라이언트와 서버를 빌드하고, 지정한 한쪽의 경과 시간과 가능한 경우 CPU 사이클을 기록합니다.

## 첫 실행

**준비:** C 컴파일러, C++20 컴파일러, CMake 3.20+, Make 또는 Ninja, `pkg-config`, GNU tar/coreutils/binutils, util-linux(`flock`, `setsid`), 시험용 인증서를 만드는 `openssl` 명령. 아래 OpenSSL 소스는 Perl과 Make로 빌드합니다. 외부 JSON 라이브러리, `jq`, 시스템 OpenSSL 개발 헤더는 필요 없습니다.

저장소 루트에서 같은 셸로 실행하세요. 예시 소스는 `curl`로 받습니다. 오프라인이라면 다운로드 대신 같은 커밋의 아카이브를 `"$archive"`에 복사하세요. 소스가 이미 `implementations/openssl/`에 있다면 첫 블록에서 `work=$(mktemp -d)`만 실행하세요.

```sh
work=$(mktemp -d)
archive="$work/openssl.tar.gz"
curl -fL -o "$archive" https://codeload.github.com/openssl/openssl/tar.gz/2d1c10a592677ff34cdf60bd59c431d835a1fc26 &&
  mkdir implementations/openssl &&
  tar -xf "$archive" --strip-components=1 -C implementations/openssl
```

예시를 빌드하고 S0(핸드셰이크만)을 한 번 측정합니다.

```sh
tools/init-submission-example.sh openssl &&
  ./bench.sh --build-only --out "$work/build" &&
  ./bench.sh --run-from "$work/build" --scenario S0 --role client \
    --auth server --warmups 0 --repetitions 1 --out "$work/s0" &&
  cat "$work/s0/cases.csv" &&
  cut -d, -f1-13 "$work/s0/results.csv"
```

`cases.csv`에서 `server,S0,client,passed,1,1`은 요청한 본 시도 1건이 검증됐다는 뜻입니다. `results.csv`의 `purpose=sample`은 본 시도, `purpose=doctor`는 사전 확인입니다. `wall_ns`는 경과 시간(ns), `cycles`는 CPU 사이클입니다. **빈칸은 미관측이지 0이 아닙니다.** 실행 실패는 `cases.csv`의 `reason`, 빌드 실패는 `"$work/build/build/native.log"`를 확인하세요.

## 다음 실행

같은 빌드로 S3(요청→응답)를 실행합니다. 빌드 폴더는 옮기지 않고, 결과는 아직 없는 위치에 만듭니다.

```sh
./bench.sh --run-from "$work/build" --scenario S3 --role client \
  --auth server --warmups 0 --repetitions 1 --out "$work/s3" &&
  cat "$work/s3/cases.csv"
```

- [내 TLS 포팅·시나리오별 측정 구간·CSV 읽기](docs/submission.md)
- [OpenSSL·wolfSSL·GnuTLS 등의 제출 예시](docs/examples/submissions/README.md)
- [이미 빌드한 TLS 앱에 SDK 연결](docs/sdk-guide.ko.md)

전체 실행 옵션은 `./bench.sh --help`에서 볼 수 있습니다.
