# 현재 검증 범위와 재확인 방법

2026년 11월 12일까지 x86_64 WSL2에서 수행한 기능·기록 일관성 검증입니다. 네이티브 Linux 성능 실험이나 ARM 재현으로 표시하지 않습니다. 결과 해석과 표는 [구현 보고서](implementation-report.md), 남은 작업은 [구현 계획](implementation-plan.md)을 따릅니다.

## 빌드·회귀 검사

가독성 리팩토링 뒤 Release 제품·Debug 시험 빌드와 전체 **93개 시험**을 통과했습니다. 마지막 기록 스트림 초기화 수정 뒤 제품·시험을 다시 빌드하고 관련 **15개 시험**도 통과했습니다. cppcheck의 프로젝트 컴파일 조건 32개와 clang-analyzer, 11개 부품 경계, Python·셸 문법을 확인했습니다. 외부 라이브러리 소스 전체에 대한 정적 검사로 확대하지 않습니다.

[검증 목록](../../artifacts/refactor-readability-1/verification.json)에 명령·로그·변경 전 소스·diff를 연결합니다. 최초 정적 검사 진단과 수정 뒤 결과는 별도 로그로 보존합니다. 이 자료를 수집할 당시에는 저장소에 Git 메타데이터가 없어 커밋이나 `git diff --check` 결과 대신 파일별 해시와 diff를 남겼습니다.

2026년 11월 12일 원격 게시 전에는 Git 이력을 복구한 상태에서 `REPEAT=1 JOBS=4 scripts/check.sh`와 `scripts/static-check.sh build "$PWD" all`을 다시 통과했습니다. Release 제품·Debug 시험 빌드, 실제 TLS 실행을 포함한 93개 시험, cppcheck·clang-analyzer와 부품 경계를 확인했습니다. Python 스크립트·시험 35개와 셸 스크립트의 문법, 커밋 대상의 `git diff --cached --check`도 통과했습니다. 논문 원본과 Zone.Identifier 파일은 커밋 대상에서 제외했습니다.

[출력 동등성 검사](../../artifacts/refactor-readability-1/output-equivalence.json)는 변경 전후 실행 파일로 만든 표준 TLS·손실·캐시·CPU 보고서 20개 파일의 바이트 일치를 확인합니다. TCP 분석의 60개 엔드포인트 파일·120개 연결 기록, CPU 자료 네 묶음의 JSON·CSV도 일치했습니다.

## 실제 TLS와 관측 검증

| 검증 | 확인한 범위 | 근거 |
|---|---|---|
| 표준 세 구현체 | 147개 실행·새 TCP 150연결. 3×3 라이브러리 조합, 네 시나리오, 두 송신 정책, 서버 인증·상호 인증, 큰 비대칭 응용 데이터 | [내부 사건 행렬](../../artifacts/internal-span-matrix-final/verification.json) |
| ML-KEM | 정상 벡터와 실제 C/AVX2 분기, 64개 실행·128연결, 동일 기반 비교 | [ML-KEM 행렬](../../artifacts/mlkem-matrix-final/verification.json), [조건·출처](../experiments/mlkem-comparison.md) |
| BiTHaC | 기준/캐시·네 시나리오·두 인증의 16개 실행. 세 모드 예비 자료 72개 역할/연결 행과 첫 연결 준비·다음 연결 캐시 사용 | [BiTHaC 요약](../../artifacts/bithac-pilot-1/bithac-summary.json), [재현 범위](../experiments/research-reproduction.md) |
| 방향별 netem | 무지연·클라이언트→서버 20ms·서버→클라이언트 20ms·양방향 10ms, 8개 실제 연결, qdisc 적용값·TLS/TCP 바이트·ACK·정리 | [방향별 검증](../../artifacts/local-directional-netem-1/verification.json) |
| 커널 송신 시각 | 세 구현체·네 시나리오·각 두 연결, 48개 역할/연결에서 SCHED/SND/ACK와 최종 제출 바이트 대응 | [송신 시각 행렬](../../artifacts/tx-timestamp-matrix-1/verification.json) |
| 속도·초기 윈도 | 양방향 1Mbit/s·5ms·initcwnd=4, 64KiB 응용 교환, 실제 TCP_INFO와 원본 패킷 대응 | [속도·윈도 검증](../../artifacts/network-tx-pilot-2/verification.json) |
| 지정·랜덤 손실 | 세 구현체·다섯 조건·60개 TLS 연결·120개 역할/연결. 지정 제거 48건의 재전송 복구, 랜덤 5%의 qdisc 제거 51건·커널 재전송 37건 | [커널 손실 행렬](../../artifacts/kernel-loss-matrix-final/verification.json) |
| 리팩토링 뒤 손실 회귀 | OpenSSL 클라이언트·Mbed TLS 서버, 새 TCP 두 연결, 양방향 32KiB. 지정 제거 4건·대응 재전송 4건, 정상 인증·응용 교환·자원 정리 | [실제 복구 검증](../../artifacts/refactor-readability-1/kernel-verification.json) |
| 관측 설정 | 시간·추적·추적+TX·CPU 수집을 각각 12개 새 프로세스 쌍에서 실행, 총 96개 역할 기록 | [관측 부담 예비 자료](../../artifacts/observation-pilot-final/observation-summary.json) |

표의 단위는 서로 다르고 CTest와 보존 행렬이 일부 겹칩니다. 모두 더해 독립 표본 수로 사용하지 않습니다. 같은 컨텍스트의 여러 연결도 독립 반복으로 세지 않습니다. 모의 어댑터 시험은 공개 계약 검증이며 실제 TLS 성공의 근거로 쓰지 않습니다.

커널 손실 검증에서는 사건·캡처 버퍼 누락 0, 요청 target의 실제 제거, BPF·보조 프로세스 정리와 호스트 네트워크 불변을 확인했습니다. 커널 관측 실행은 initial user namespace의 root이며 일반 user namespace 실행과 다른 조건입니다. 랜덤 손실 seed는 고정되지 않았으므로 실제 제거 기록을 기준으로 해석합니다.

## 재분석과 검증 명령

의존성과 시험 PKI를 준비한 뒤 저장소 루트에서 실행합니다. 일반 검사와 관리자 권한이 필요한 커널 검증은 별도입니다.

```sh
REPEAT=1 JOBS=6 scripts/check.sh
scripts/static-check.sh build "$PWD" all

sudo python3 scripts/kernel-loss-study.py run --build build --pki pki/default \
  --output results/kernel-loss
python3 scripts/kernel-loss-study.py analyze --build build --output results/kernel-loss

python3 scripts/implementation-report.py
```

첫 두 명령은 빌드·시험·정적 검사를, 커널 명령은 실제 TLS 손실 복구를 확인합니다. 보고서 생성기는 보존된 검증 자료를 읽으며 시험을 새로 실행하지 않습니다. [재분석 대조](../../artifacts/verification-implementation-final/reanalysis.json)에서 원자료 2,081개 파일의 불변과 분석 여덟 묶음의 바이트 일치를 확인했고, [보고서 재생성 검사](../../artifacts/verification-implementation-final/report-verification.json)도 보존합니다.

## 해석 한계

CPU 함수 비중은 수집한 `perf.data`의 표본이며 총 CPU 계수와 다릅니다. 수집 당시 바이너리·build ID가 없으면 누락, 해석 불가 함수는 unknown으로 남깁니다. 짧은 구간의 소수 표본으로 안정된 함수 비중을 주장하지 않습니다. 도구·커널 경고와 실패 시행은 원자료에 보존합니다. 구체 범위는 [CPU 분석](../analysis/cpu-profiling.md)을 따릅니다.

원본 패킷·커널 사건·소켓 시각은 관측 위치가 다릅니다. 소프트웨어 프레임을 물리 NIC 프레임으로, 패킷 중첩을 실제 제거 기록으로 바꾸어 해석하지 않습니다. 실패·누락 자료는 성공 자료로 대체하지 않습니다.

네이티브 Linux·ARM, 본 실험 조건·통계 동결과 장비별 관측 부담 평가, BiTHaC 논문의 정확한 timer 경계 대조는 미완료입니다. 현재 검증 통과는 로컬 구현의 기능과 원자료 일관성에 한정됩니다.
