# 문서 안내

현재 동작의 기준 문서는 [프레임워크 설계](design/architecture.md)입니다. 설계 논의는 [다음 설계 논의](design/discussion.md)에서 시작합니다. 현재 사실, 제안, 과거 검증 결과를 서로 다른 문서로 구별합니다.

| 읽는 목적 | 문서의 책임 |
|---|---|
| 빌드·첫 실행 | [README](../README.md), [도구 안내](../scripts/README.md) |
| 설계 이해 | [프레임워크 설계](design/architecture.md): 실행·수명·비용·자료·해석의 경계 |
| 다음 변경 결정 | [설계 논의](design/discussion.md): 현재 제약, 선택지, 권고와 완료 기준 |
| 구현체 연결 | [공개 헤더](../include/turtle/implementation.h), [구현자 안내](design/implementation-guide.md) |
| 명세·원자료 해석 | [실행·사건 계약](analysis/record-format.md), [보고서·통계](analysis/reporting.md) |
| 연구 기능 실행 | [연구 기능](experiments/research.md), [네트워크](analysis/network.md), [CPU 표본](analysis/cpu-profiling.md) |
| 범위·변경 이유 | [구현 계획](project/implementation-plan.md), [결정 기록](project/DECISIONS.md) |
| 실행 증거 확인 | [검증 기록](project/validation.md): 실행 날짜·환경·검증 범위·자료 위치 |
| 빌드·자료 정리 | [작업 공간 관리](project/workspace.md): 활성 경로·보존 경로·정리 원장 |

구형 API 사용법과 완료된 임시 계획을 현재 설계로 병렬 제공하지 않습니다. 고정 의존성의 원본과 참고 문헌, 과거 실험의 원자료는 현재 API 문서와 구별해 보존합니다. 문서 안의 로컬 증거 링크는 해당 자료를 보유한 작업 공간에서 열 수 있습니다.
