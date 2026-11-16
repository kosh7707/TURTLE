# CPU 표본

CPU 표본은 일반 시간 표본과 분리한 실행에서 수집합니다. 엔드포인트별로 perf record를 시작하고 원본 `perf.data`, 이벤트 설정, 실행 당시 바이너리·공유 라이브러리와 build ID·SHA-256을 보존합니다. 현재 빌드의 다른 바이너리를 자동으로 가져와 심볼을 채우지 않습니다. 보존한 symfs를 지정해 재분석합니다.

```sh
python3 scripts/cpu-profile.py run --perf /path/to/perf --event cpu-clock:u \
  --connections 40 --output results/cpu
python3 scripts/cpu-profile.py analyze --perf /path/to/perf --output results/cpu
```

`cycles:u` 또는 `cpu-clock:u`를 명시적으로 선택합니다. 필요한 권한과 커널 지원은 환경에 따라 다릅니다. 하드웨어 cycles 수집 실패를 다른 이벤트의 성공으로 숨기지 않습니다. frequency와 실제 이벤트 속성을 산출물에 기록합니다.

perf 시계는 CLOCK_MONOTONIC입니다. 같은 호스트에서 실행한 해당 엔드포인트 PID의 주 스레드 표본만 준비·연결·시나리오와 상세 사건 구간에 대응합니다. 부모 시나리오와 하위 구간은 별도 보기이므로 표본 수를 서로 더하지 않습니다. 짧은 구간에 표본이 없으면 missing이지 함수 실행 비용 0이 아닙니다.

보고서는 함수·모듈별 sample count와 period 비중입니다. 정확한 함수 호출 시간, 호출 횟수, 총 CPU 시간으로 환산하지 않습니다. 해석하지 못한 행, lost 사건, 심볼 미확인과 바이너리 출처 누락을 남깁니다. 가상 VDSO처럼 보존하지 못한 객체의 심볼을 현재 시스템에서 추정하지 않습니다. CPU 수집 표지가 있는 실행은 일반 시간의 자동 부트스트랩 비교에서 제외합니다.
