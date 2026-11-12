# TURTLE 문서 안내

현재 구현을 읽고 실행하는 데 필요한 문서를 모았습니다. 빌드와 첫 실행은 [프로젝트 README](../README.md), 완료 범위와 남은 작업은 [구현 계획](project/implementation-plan.md)에서 시작합니다.

구성별 빌드·시험·인증서 준비 명령과 출력 경로는 [scripts 사용법](../scripts/README.md)에 모았습니다.

## 폴더 구성

| 폴더 | 문서 종류 |
|---|---|
| [design/](design/) | 구조·소유권, 어댑터, 실행·계측 계약 |
| [analysis/](analysis/) | 원자료 형식, 보고서 해석, TCP·CPU 분석 |
| [experiments/](experiments/) | 논문 기법 재현, ML-KEM 비교, 모의 CA 실험 |
| [project/](project/) | 구현 계획·보고서, 설계 결정, 검증 범위 |
| [references/](references/) | 실제 논문·RFC 원문 |

## 코드와 계약을 읽는 순서

1. [구조와 소유권](design/architecture.md): 부품 관계, 객체 수명, 실제 코드 읽기 순서
2. [어댑터 작성 안내](design/adapter-guide.md): 공개 ABI와 라이브러리 연결 방법
3. [엔드포인트 실행](design/runtime.md): 프로세스·TCP·비차단 진행·측정 경계
4. [공통 실행·계측 계약](design/prototype.md): 네 시나리오, 송신 정책, 구현별 내부 사건 범위
5. [원자료 형식](analysis/record-format.md): 파일·사건·가용성·버전 의미
6. [보고서와 비교 조건](analysis/reporting.md): 측정 구간, 집계, 자동 비교 적격성

## 실험과 분석

| 문서 | 내용 |
|---|---|
| [TCP 분석](analysis/tcp-analysis.md) | veth·netem, 원본 패킷, 송신 시각, 지정 손실·재전송 |
| [CPU 분석](analysis/cpu-profiling.md) | perf 수집, 바이너리 보존, 함수·모듈 표본 해석 |
| [논문 기법 재현](experiments/research-reproduction.md) | 후보 출처와 BiTHaC의 실제 캐싱·재현 가정 |
| [ML-KEM 비교](experiments/mlkem-comparison.md) | 같은 기반의 C/AVX2 비교 조건과 실행 절차 |
| [모의 CA](experiments/mock-ca.md) | 표준 TLS와 분리한 합성 인증서 조회·캐시·서비스 계측 |

## 현재 상태와 근거

| 문서 | 내용 |
|---|---|
| [구현 계획](project/implementation-plan.md) | 단계별 통과 범위와 남은 연구 작업 |
| [구현 보고서](project/implementation-report.md) | 현재 검증 목록에서 재생성한 실행·분석 근거와 확인 한계 |
| [구현 결정](project/DECISIONS.md) | 현재 설계와 선택 이유 |
| [검증 범위](project/validation.md) | 빌드·실제 TLS·회귀 검증 근거와 재확인 명령 |
| [의도된 동작 점검](project/intent-audit.md) | 정상 시나리오 198쌍의 독립 대조, 발견한 기록·표시 오류와 수정 근거 |
| [로컬 웹·재현](project/local-web-reproduction.md) | 별도 실험 웹, 새 소스·의존성·설치 재현, 산출물 보관 목록 |

## 논문과 RFC 원문

`references/`에는 실제 논문·RFC 원문만 둡니다. 후보 조사, 구현 설명과 연구 계획은 위 문서에서 관리합니다.

- [Benchmarking Post-Quantum Cryptography in TLS](<references/Benchmarking Post-Quantum Cryptography in TLS.pdf>)
- [The Performance of Post-Quantum TLS 1.3](<references/The Performance of Post-Quantum TLS 1.3.pdf>)
- [RFC 9846 — The Transport Layer Security (TLS) Protocol Version 1.3](references/rfc9846.txt)
