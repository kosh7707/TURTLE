# 선택적 유틸

프레임워크는 `src/`의 C++ 코드이며 이 디렉터리가 없어도 빌드·TLS 실행·계측·분석을 수행한다.

| 도구 | 입력과 책임 |
|---|---|
| `report/report.py` | manifest와 C++ 분석 v4 → 반복 통계·JSON·CSV·Markdown·HTML |
| `dependencies.py` | 공식 고정 소스 다운로드·해시 확인·별도 의존성 준비 |
| `check.py` | 도구 구문·CMake 부품 경계·clang-tidy 실행 보조 |
| `check_independence.py` | Python·tools·외부 작업 공간·네트워크 없는 격리 검증을 밖에서 실행 |
| `netns-exec.sh` | 선택적 사용자·네트워크·마운트 네임스페이스 래퍼 |
| `wireshark/turtle.lua` | Wireshark의 프레임·원래 TLS 레코드 표시 |
| `wireshark/check_capture.py` | TShark 독립 대조와 GUI 열기 |

보고서 도구는 원자료 해석·수집·계측 유효성 판정을 하지 않는다. 프레임워크 코드나 내부 Python 패키지를 import하지 않는다. Python 표준 라이브러리만 사용한다.

사용법은 [README](../README.md), [의존성 준비](../docs/project/dependencies.md), [독립 검증](../docs/project/independence.md), [Wireshark](../docs/project/wireshark.md)를 따른다.
