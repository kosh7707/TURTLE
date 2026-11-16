# 연구 실행 도구

스크립트는 [README](../README.md)의 새 메시지 소스 계약을 사용합니다. `build-deps.sh`의 기본 실행, 빌드, 시험, 분석은 네트워크 다운로드 없이 동작합니다. 의존성을 처음 준비할 때만 `--fetch`를 사용합니다.

| 도구 | 책임 |
|---|---|
| dependencies.py / build-deps.sh | 고정 원본 추출, 경계 패치, 정적 의존성 빌드 |
| build.sh / provenance.py | 구현체별 엔드포인트 빌드와 소스·바이너리 출처 저장 |
| make-pki.sh | 정상 시험용 CA·인증서; CERT_PADDING으로 큰 인증서 시험 |
| run.py | 새 독립 프로세스 한 쌍 |
| study.py | seed를 저장한 배치 내 무작위 실행 원장 |
| report.py | 새 사건 계약의 역할·컨텍스트·연결별 JSON·CSV |
| mockca.py | 합성 객체 조회 서비스 |
| network.py / packets.py | 소유 네임스페이스·netem·pcap과 바이트 대응 |
| build-kernel-observer.py / kernel_observer.py | 고정 BPF 빌드, 소유 커널 링크와 원본 사건 |
| cpu-profile.py | 별도 perf.data와 실행 당시 심볼·구간 분석 |
| verify-mlkem-build.py | 두 연산 파일 이외의 코드·데이터 동일성 검사 |
| static-check.py | 부품 방향·공개 계약·금지된 전체 handshake 호출 검사, 선택적 clang-tidy |

구형 실행 스크립트의 별칭이나 형식 변환 경로는 없습니다.

기본 소스 빌드와 커널 관측기 출력은 `build-message/`, 별도 시험 빌드는 `build-message-tests/`, 시험 PKI 생성 기본값은 `pki/default/`입니다. 과거 검증 경로는 활성 빌드로 재사용하지 않습니다. 원본 캐시·현재 의존성·원자료·생성물의 정리 기준은 [작업 공간 관리](../docs/project/workspace.md)에 있습니다.
