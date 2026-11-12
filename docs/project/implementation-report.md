# TURTLE 현재 구현·검증 보고서

검증일은 2026-11-12이며 실행 환경은 x86_64 WSL2 / Linux 6.18.58.1-microsoft-standard-WSL2입니다. 이 문서는 명시한 검증 목록에서 생성하며 과거 성능 표나 개인 경로를 찾아 결합하지 않습니다.

독립 `turtle-client`와 `turtle-server`는 IPv4:Port의 데이터 TCP와 제어 TCP로 실행합니다. 준비 단계에서 시나리오·실행 ID·지원·컨텍스트·버퍼 준비를 확인하고 첫 측정 연결을 보존합니다. 기본 내장 연결과 명시적 모듈 연결을 구별하며 프로그램 진입 전 로딩 비용은 미관측입니다.

아래 기존 독립 엔드포인트 검증은 TLS 원자료 schema 3, 측정 계약 개정 3, 어댑터 ABI 3, 제어 프로토콜 2의 기록입니다. 이후 계측 검증에서 새 실행의 종료를 마지막 TLS API 성공 반환으로 정하고 측정 계약을 4로 올렸습니다. 최신 수정·실행 근거는 [계측 검증 기록](validation.md#계측-의도와-실제-동작의-대조)을 따릅니다. 개정 3의 수치를 새 결과로 바꾸지 않습니다. TLS schema 1·2 판독과 이전 실행 명령·평면 프로필·부모 지휘 경로는 제거했습니다. 서비스·실험 원장·해독·패킷·분석 산출물의 독립 버전 번호는 별도로 관리합니다.

| 검사 | 확인한 범위 | 자료 |
|---|---|---|
| 소스 빌드 | 경고를 오류로 처리한 릴리스 구성 8개; 소스와 시험 빌드 분리 | [근거](../../artifacts/refactor-current/build-refresh.json) |
| 독립 의존성 | 클라이언트·서버·모듈 클라이언트·분석 전용 4구성의 실제 실행 파일과 링크 확인 | [근거](../../artifacts/refactor-current/build-isolation.json) |
| 전체 회귀 | 86개 통과; 실제 세 TLS 라이브러리·조회·컨텍스트 재사용·BiTHaC 캐시 호출·ML-KEM 분기 포함 | [근거](../../artifacts/refactor-current/logs/ctest-final.log) |
| 정적 분석 | 프로젝트 번역 단위 35개에 cppcheck·clang-analyzer 적용 | [근거](../../artifacts/refactor-current/logs/static.log) |
| 독립 TLS 실행 | 내장 48쌍·내장/모듈 혼합 24쌍·라이브러리 간 24쌍; 별도 작업·출력 폴더와 양쪽 보고 | [근거](../../artifacts/refactor-current/pairs/verification.json) |
| 네트워크 | 양방향 10ms 지연; 제어/데이터 분리; 두 TLS 연결의 지정 손실 4건·재전송 4건·정리 확인 | [근거](../../artifacts/refactor-current/network.json) |
| 커널 포트 분류 | 실제 BPF 프로그램에 임시/서비스 포트 중첩 12조건 실행; 제어 제외·최초 데이터 손실·재전송 통과 | [근거](../../artifacts/refactor-current/kernel-flow-final.json) |
| 분류 오류의 재분석 | 임시 포트 44331의 최초 실패 캡처를 보존하고 동일 TLS 바이트의 대응 확인 | [근거](../../artifacts/refactor-current/port-collision.json) |
| 내장 CPU 표본 | 별도 2시도; 내장 컨텍스트 셋업과 모듈 로드 시작을 구별; 빈 구간은 missing | [근거](../../artifacts/refactor-current/cpu-builtin/cpu-profile.json) |
| 혼합 CPU 표본 | 별도 2시도; 내장 컨텍스트 셋업과 모듈 로드 시작을 구별; 빈 구간은 missing | [근거](../../artifacts/refactor-current/cpu-mixed/cpu-profile.json) |
| 자료 재생성 | 100개 보고 폴더의 304파일·CPU 요약 2개가 바이트 단위 동일; 원자료 1518파일 불변 | [근거](../../artifacts/refactor-current/replay.json) |
| 구조·문서 품질 | 11개 부품 포함 경계·자체 시험, Python·셸 구문, 문서 링크, 공백 검사 | [근거](../../artifacts/refactor-current/quality.json) |

검사 성공은 정상 TLS 기능과 자료 처리의 확인입니다. 성능 순위, 물리 NIC 통과, 논문 성능 수치의 재현이나 전체 연구 완료를 뜻하지 않습니다. 루프백은 커널 TCP/IP이고 veth는 가상 인터페이스를 통과합니다.

남은 확인 사항은 다음과 같습니다.

- 물리 NIC 통과와 실제 ARM 빌드·실행은 미검증입니다.
- 네이티브 Linux 본 성능 실험과 장비별 관측 부담 평가는 별도 작업입니다.
- 배포 크기·RSS와 원격 배포·재시작·결과 회수 자동화는 완료 범위에 포함하지 않습니다.
- BiTHaC 논문의 정확한 timer 경계는 미확정이며 ML-KEM C/AVX2 비교를 AVX-512 논문 재현으로 표시하지 않습니다.
- WSL 기능 검증은 성능 순위나 본 연구 전체의 완료를 뜻하지 않습니다.

전체 명령과 파일 출처는 [검증 목록](../../artifacts/refactor-current/verification.json)에 있습니다. 측정 경계와 운영 명령은 [실행 계약](../design/runtime.md), 재실행 절차는 [검증 기록](validation.md)을 따릅니다.

```sh
python3 scripts/implementation-report.py \
  --verification artifacts/refactor-current/verification.json
```
