# 첫 제출: 여기 있는 두 파일을 수정하세요

이 디렉터리는 한 번에 한 TLS 구현을 받습니다. **[build.sh](build.sh)**와 **[implementation.cpp](implementation.cpp)**는 편집을 시작할 수 있는 템플릿이지 TLS 라이브러리가 아닙니다. 한쪽이라도 기본 템플릿 그대로라면 `./bench.sh`는 해당 파일을 알려주고 종료합니다(코드 2). 빌드 캐시·결과 디렉터리도 만들지 않습니다.

1. 원본을 `implementations/<내-소스>/`에 둡니다. 이름은 자유이며 기존 소스가 있다면 그대로 사용합니다.
2. **직접 연결:** `build.sh WORK PREFIX [인자...]`에서 원래 방식으로 라이브러리를 빌드해 `PREFIX`에 헤더·공유 라이브러리·pkg-config 정보를 설치합니다. `implementation.cpp`에서는 [공개 함수 7개](../src/include/turtle/implementation.hpp)를 연결합니다. [레시피 계약](../docs/build-contract.ko.md) · [함수별 동작](../docs/submission.md).
3. **또는 예시로 시작:** 예를 들어 원본이 `implementations/openssl/`에 있다면 저장소 루트에서 아래 두 줄을 실행합니다. 예시 선택이 성공해야 빌드가 시작됩니다. 선택 도구는 두 편집 파일만 설치하며 원본을 받거나 바꾸지 않습니다.

   ```sh
   tools/init-submission-example.sh openssl && ./bench.sh --build-only
   ```

직접 구현한 경우에는 `./bench.sh --build-only`만 실행합니다. 성공하면 출력된 `Results:` 경로 아래에 `build/bin/client`와 `build/bin/server`가 생깁니다. **아직 TLS 연결이나 측정은 없습니다.** 같은 빌드로 실행하려면 `./bench.sh --resume "$job"`을 사용합니다(`job`은 출력된 결과 경로).

예시 설치는 두 대상 각각이 없거나 배포 템플릿과 내용이 같을 때만 진행합니다. 편집한 파일이나 심볼릭 링크가 있으면 그대로 두고 중단합니다. 이미 작업 중이라면 [예시 모음](../docs/examples/submissions/README.md)을 참고해 필요한 부분만 옮기세요. 어떤 예시도 자동 선택되지 않습니다. 선택 중에는 두 파일의 편집을 끝내 두세요. 동시에 변경돼 복원이 멈추면 도구가 출력한 `.submission-example.*/old/`의 사본을 확인한 뒤 정리하세요.

**Git에 남는 것:** README와 두 편집 파일은 일반 `git add` 대상으로, 변경 내용을 `git status --short -- implementations/`에서 확인할 수 있습니다. 이 폴더의 다른 원본·키·로컬 파일은 기본적으로 무시됩니다. 이미 추적 중인 파일을 숨겨 주는 규칙은 아니므로 두 편집 파일에 비밀 값을 넣지 마세요.

## 기존 작업 트리를 업데이트한다면

**업데이트 전에** 두 파일부터 확인하세요. 예전 버전은 두 이름을 무시했으므로 `git status`가 깨끗해도 기본 `git pull`이나 브랜치 전환이 로컬 작업을 배포 템플릿으로 바꿀 수 있습니다. 예시 설치 도구는 **업데이트 이후**의 편집본만 보호하며 Git 자체의 동작을 바꾸지 않습니다.

가장 안전한 방법은 별도 디렉터리에 새 checkout을 받아 기존 파일과 비교하는 것입니다. 현재 트리를 유지한다면 두 파일을 작업 트리 밖에 백업하고 내용이 같은지 확인한 뒤, upstream이 설정된 브랜치에서 아래처럼 진행하세요.

```sh
git fetch && git merge --ff-only --no-overwrite-ignore '@{upstream}'
```

충돌로 중단되면 기존 두 파일을 먼저 보존하세요. 강제 checkout이나 `git clean -x`로 해결하지 마세요. `git stash -u`도 무시된 파일을 포함하지 않습니다.
