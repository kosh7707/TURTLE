# 실행 예제

[one-sided-s3.json](one-sided-s3.json)은 현재 `turtle check/run`이 받는 네이티브 클라이언트 프로필이다. 독립 실행 파일 `gnutls-cli`의 평문 입출력을 사용한다. 설치하거나 빌드한 해당 프로그램을 PATH에 둔다. [issue-test-leaves.sh](issue-test-leaves.sh)는 일회성 시험 CA와 양 역할의 신원 파일을 만드는 로컬 fixture다.

`compare.json`, `mtls-s3.json`, `perf-counters.json`, `perf-sampling.json`은 **이전 컨트롤러의 역사적 명세**다. 새 네이티브 실행 예제가 아니다. 이전 시행의 재분석에는 해당 실행 디렉터리(`manifest.json` 포함)를 `turtle analyze RUN`에 전달한다.
