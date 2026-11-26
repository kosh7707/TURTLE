# 내 TLS 소스 제출

한 슬롯에 TLS 구현 하나를 둡니다. [`build.sh`](build.sh)와 [`implementation.cpp`](implementation.cpp)는 TLS를 실행하지 않는 시작 파일입니다.

1. TLS 원본을 이 디렉터리 아래에 둡니다. 직접 만든 레시피는 원본 폴더 이름을 자유롭게 정할 수 있습니다.
2. [레시피 계약](../docs/submission.md#빌드-레시피)에 맞춰 `build.sh`를 편집하고 실행 권한을 유지하세요. `implementation.cpp`에는 [일곱 함수](../docs/submission.md#포팅)를 구현합니다. 또는 [예시 하나](../docs/examples/submissions/README.md)를 선택하세요. 선택 도구는 편집한 파일이나 심볼릭 링크를 덮어쓰지 않습니다.
3. 저장소 루트에서 `./bench.sh --build-only`로 두 역할을 링크한 뒤 `./bench.sh --run-from JOB --scenario S0`을 실행하세요(`JOB`은 출력된 빌드 경로). [CSV 결과 확인](../docs/submission.md#결과). 시작 파일이 그대로라면 종료 코드 2로 멈추며 빌드나 측정을 시작하지 않습니다.

두 시작 파일은 Git 추적 대상입니다. 원본 폴더나 키는 기본적으로 무시되지만, 두 파일 안에 비밀을 넣지 마세요.
