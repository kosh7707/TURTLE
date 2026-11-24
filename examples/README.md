# 실행 예제

준비된 TLS 세션을 SDK에 연결하는 예시는 [엔드포인트 연동 안내](../docs/endpoint.md)와 [독립 C 앱으로 S2 실행](../README.md)에 있다. 자신의 빌드에서 `turtle::endpoint`에 링크한다. 다음 프로필은 SDK 없이 기존 응용의 표준 입출력을 관찰하는 예다.

[one-sided-s3.json](one-sided-s3.json)은 현재 `turtle check/run`이 받는 네이티브 클라이언트 프로필이다. 독립 실행 파일 `gnutls-cli`의 평문 입출력을 사용한다. 설치하거나 빌드한 해당 프로그램을 PATH에 둔다. [issue-test-leaves.sh](issue-test-leaves.sh)는 일회성 시험 CA와 양 역할의 신원 파일을 만드는 로컬 fixture다.

`compare.json`, `mtls-s3.json`, `perf-counters.json`, `perf-sampling.json`은 **이전 컨트롤러의 역사적 명세**다. 새 네이티브 실행 예제가 아니다. 이전 시행의 재분석에는 해당 실행 디렉터리(`manifest.json` 포함)를 `turtle analyze RUN`에 전달한다.
