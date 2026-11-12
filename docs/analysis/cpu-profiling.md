# 별도 실행의 CPU 표본과 perf.data

`scripts/cpu-profile.py`는 실제 `perf record` 실행과 `perf.data`를 보존하고, `perf script` 표본을 TURTLE의 엔드포인트 PID·주 스레드·측정 구간에 연결합니다. 기존 `perf_event_open`의 총 사이클·명령어 계수와 다른 자료입니다. 표본의 함수·모듈 비중을 총 CPU 시간이나 정확한 함수 호출 비용으로 바꾸지 않습니다.

```sh
python3 scripts/cpu-profile.py run --perf /path/to/perf --build build \
  --pki pki/default --client mlkem-c --server mlkem-c --group ML_KEM_768 \
  --samples 3 --event cycles:u --frequency 997 --no-affinity \
  --output results/cpu-mlkem-c
python3 scripts/cpu-profile.py analyze --perf /path/to/perf \
  --output results/cpu-mlkem-c
```

`--perf`를 생략하면 PATH의 도구를 사용합니다. 바이너리 build ID 대조에는 binutils의 `readelf`도 필요합니다. 실행은 상호 인증·클라이언트 요청/서버 응답, 컨텍스트당 연결 1개·워밍업 0회입니다. 일반 시간 실행과 별도 프로세스 쌍을 사용합니다. `--cpu-profile`은 외부 수집을 나타내는 원자료 표지이며 이 플래그 자체가 수집기를 시작하지는 않습니다. 실제 수집 증거는 `perf.data`, 명령·종료 코드와 표본입니다. 일반 보고서와 반복 컨텍스트 보고서는 어느 한 엔드포인트라도 이 표지가 있으면 시간값을 진단 자료로 남기고 자동 성능 비교에서 제외합니다.

## 범위와 산출물

수집은 지휘자에서 상속한 task 이벤트를 사용합니다. 분석은 각 역할의 새 PID에서 PID와 같은 TID의 표본만 고릅니다. 다른 역할·지휘자·다른 스레드를 합산하지 않습니다. 스케줄러를 따라 이동하는 task 범위이며 코어별 귀속과 호출 스택은 제공하지 않습니다. 이벤트는 `cycles:u`, `cpu-clock:u`, `cycles`, `cpu-clock` 중 명시하고 실제 설정을 `perf.events.txt`에 보존합니다. 커널 포함 이벤트를 요청했을 때 권한이 없으면 다른 이벤트로 자동 변경하지 않습니다.

`perf record --clockid mono`와 `perf script --ns`를 사용해 원자료의 CLOCK_MONOTONIC 구간에 연결합니다. 모듈 로드 시작→컨텍스트 해제 완료와 연결의 주 측정 구간을 따로 보고합니다. 후자의 시작·끝 순번은 JSONL에 남아 있습니다. 모듈→해제 구간은 준비·동기화·정리를 포함하지만 프로세스 전체 수명은 아닙니다.

- `perf.data`, `record.stdout`, `record.stdout.stderr`: 원본 표본 자료와 실행 로그입니다.
- `profile-manifest.json`, `perf.version.txt`, `perf.events.txt`, `perf.header.txt`: 명령, 커널·도구 판, 이벤트 설정입니다.
- `perf.buildids.txt`, `binary-provenance.json`, `symbols/`: perf.data에 기록된 build ID와 일치하는 실행 파일·공유 라이브러리의 복사본 및 SHA-256입니다. 원래 절대 경로를 symbols 아래에 보존합니다.
- `perf.script.txt`와 각 `.stderr`: 해석한 전체 표본과 경고이며 범위 밖 표본도 보존합니다.
- `cpu-profile.json`, `cpu-functions.csv`: 엔드포인트·구간별 함수/모듈 표본 수, period 합·비중, 경과·스레드 CPU 시간과 바이너리 해시입니다.

주파수 기반 수집에서는 표본마다 `period`가 다를 수 있으므로 비중은 표본 개수가 아닌 period 가중치로 계산합니다. 스레드 CPU 시간은 사용자+커널 합이며 `cycles:u`의 사용자 전용 표본과 범위가 다릅니다. `[unknown]` 표본도 분모에 남깁니다. 표본이 없는 짧은 구간은 `missing/no_perf_samples_in_window`, 값은 null입니다. 해석하지 못한 행·lost 기록·실패 엔드포인트를 보존하고 전체 분석을 완전한 자료로 표시하지 않습니다. 재분석은 debuginfod 다운로드를 사용하지 않습니다.

수집 직후 파일 기반 바이너리를 복사하고 build ID를 대조합니다. 재분석은 저장한 파일의 해시를 확인한 뒤 `perf script --symfs symbols/`를 사용하므로 나중에 빌드한 실행 파일에 의존하지 않습니다. 저장본이 없거나 당시 ID와 다르면 관측 누락을 기록합니다. 별도의 debug-info 파일·커널 심볼까지 보존한다고 주장하지 않으며, 해석되지 않는 함수는 계속 unknown으로 남습니다. [perf script의 symfs 계약](https://raw.githubusercontent.com/torvalds/linux/master/tools/perf/Documentation/perf-script.txt)

## 현재 확인과 한계

현재 WSL에는 `perf` 명령이 없어 Ubuntu 패키지를 사용자 전용 `.deps/tools/perf/`에 풀었습니다. 시스템 패키지나 커널 설정은 바꾸지 않았습니다. 패키지 출처·SHA-256·실제 도구 판은 `.deps/manifests/perf-tools.json`에 기록합니다. 사용한 도구는 `perf version 7.0.14`, 커널은 `6.18.58.1-microsoft-standard-WSL2`입니다.

`artifacts/cpu-mlkem-c-2/`과 `artifacts/cpu-mlkem-avx2-2/`는 서버를 C로 고정하고 클라이언트를 바꾼 각 3개 프로세스 쌍입니다. 원본 표본은 각각 116개·150개이며 역할당 모듈→해제와 연결 구간을 나누어 총 12개 구간을 보고합니다. 짧은 주 구간의 표본 수는 4~8개여서 함수 비중의 안정성이나 최적화율을 주장하지 않습니다.

이 도구·커널 조합에서 header 전용 조회는 `Invalid HEADER_EVENT_DESC: nre=1 sz=144 (min 64)` 경고를 냈습니다. 실제 `perf script`와 `evlist -v`는 성공했고 이벤트의 사용자/커널 범위·inherit·clockid와 표본을 확인했습니다. header 경고와 `/proc/schedstat` 조회 경고는 원본 stderr 및 요약의 `tool_warnings`에 남겨 메타데이터 제한을 드러냅니다. 네이티브 Linux에서는 도구·커널 조합과 관측 부담을 다시 검증해야 합니다. 이 실행을 일반 시간 성능 실험으로 사용하지 않습니다.

## 가상 객체와 관측 부담 예비실행

perf는 vDSO를 `/tmp/perf-vdso.so-*`에 잠시 내보냈다가 지울 수 있습니다. build ID 없는 이 항목은 저장된 사용자 라이브러리와 구별하며 해당 함수 이름을 unknown으로 유지합니다. 표본과 period 분모는 삭제하지 않습니다. 일반 파일의 build ID 부재·불일치나 저장본 변경은 계속 missing입니다. [perf의 vDSO 처리](https://github.com/torvalds/linux/blob/v6.18/tools/perf/util/vdso.c)

`scripts/observation-study.py`는 OpenSSL 상호 인증·32바이트 양방향·컨텍스트당 새 연결 하나·워밍업 0을 고정하고 시간, 상세 추적, 추적+TX 시각, CPU 프로파일링을 별도 실행합니다. 블록 안 순서를 seed로 섞고 원래 실행 결과와 재분석 상태를 따로 보존합니다. `artifacts/observation-pilot-final/`은 4블록×3표본으로 조건별 12개 프로세스 쌍입니다.

```sh
python3 scripts/observation-study.py run --build build --pki pki/default \
  --perf .deps/tools/perf/bin/perf --output results/observation-pilot
python3 scripts/observation-study.py analyze --build build --output results/observation-pilot
```

출력은 역할별 주 구간의 경과·스레드 CPU 원값, 중앙값·사분위수와 시간 모드 대비 중앙값 차이입니다. WSL의 부하·가상화 변동을 포함하며 전체 계측 비용이나 보편적 부담률을 뜻하지 않습니다. 패킷·BPF 수집 부담은 네이티브 환경에서 같은 권한·토폴로지로 평가해야 합니다.
