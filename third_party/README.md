# 포함한 의존성

`nlohmann/json.hpp`는 nlohmann JSON 3.11.3이며 MIT 라이선스는 같은 디렉터리의 `LICENSE.MIT`에 있습니다. 실행 명세, 준비 제어와 측정 이후의 JSON 기록에 사용합니다. 프로토콜 측정 구간에서 JSON을 해석하거나 출력하지 않습니다. 헤더와 라이선스 해시는 빌드 manifest에 보존합니다.

TLS 라이브러리의 고정 버전·원본 해시·커밋과 패치 적용은 `scripts/dependencies.py`가 관리합니다. 이 디렉터리에 시스템 TLS 라이브러리나 다른 버전의 호환 헤더를 복사하지 않습니다.
