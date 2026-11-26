# 빌드 연구에서 제품으로 옮긴 것

이 문서는 `TURTLE-build-study`의 어느 결정을 어디서 유지하는지 설명한다. 그 폴더에서 스크립트를 호출하거나 그 안의 헤더·라이브러리를 빌드에 넣지 않는다. 역사적 실험의 수치나 링크 성공은 [이번 동작 검증](scenario-validation.ko.md)의 표본이 아니다.

| 연구 원본 (연구 폴더 기준) | 현행 근거 / 이관 판단 |
|---|---|
| `build-methodology.ko.md`, `build-pattern.ko.md`, `figures/turtle-build-flow.*` | A는 원본 방식으로 SDK를 설치한다. B는 중립 ABI와 두 main을 소유한다. A와 B를 동시에 아는 C를 한 번 컴파일해 각 링크에 넣는다. 네이티브 빌드·컴파일의 생성 헤더·링커 맵·실행 중 적재 파일은 각각 다른 증거다. 이 설계는 [계약](build-contract.ko.md), [인터페이스](../src/include/turtle/implementation.hpp), [제출 방법](submission.md)에 통합했다. 당시의 축소 프로브/도식은 현행 제품 API로 출하하지 않는다. |
| `build-criteria.ko.md`, `experiments/20261126T0132Z/{protocol,criteria}.ko.md` | 원본 빌드 변경/코어 벤더 등록/공개 옵션 전사/수동 산출물 복사 없이 두 역할을 링크한다. 동일 소비 계획은 묶고, 유효 계획이 다르면 연구자가 선택하며, 해결되지 않은 항목을 추측하지 않는다. 첫 설치 시 헤더 전체의 출처까지 증명하는 계약은 아니다. 현행 범위와 합격선은 [빌드 계약](build-contract.ko.md)과 [검증 지시](../task.md#2-빌드-검증)로 통합했다. |
| `experiments/20261126T0146Z/builder-controls/root/implementations/build.sh`, `results.tsv`, `entry-controls/` | 연구용 alpha/alias/beta와 unresolved 대조를 [휴대용 합성 레시피](../tests/fixtures/submission-recipe.sh)와 [실제 bench.sh 회귀](../tests/submission-build-contract.sh)에 통합했다. 같은 소비 옵션의 별칭은 자동으로 하나, 다른 두 DSO는 선택 전 링크 미발행, 명시적 재개는 선택한 DSO만, 선언된 DSO 부재 및 설치 후 생성 헤더 변경은 거절한다. 틀린 native 인자·실패 코드도 검사한다. 별도 축소 링커를 제품과 병행하지 않는다. |
| `evidence/{final-matrix.txt,wrong-config-header-control.log,same-binary-loader-control.log}`, `experiments/20261126T0146Z/{audit-matrix.sh,report.sh}` | 같은 이름의 라이브러리나 컴파일 성공은 출처가 아니다. 현재는 [.d/두 map/해시 검사](../tools/validation/build-matrix.sh)와 [실제 연결 맵·양쪽 transcript 확인](../tools/validation/index-matrix.sh)으로 재현한다. 초기 헤더 오구성과 로더 대조의 원본 로그는 역사 자료로 보존한다. |
| `experiments/{examples-*,openssl-doc-*,contract-handoff-*,mbedtls-*}/` | 현행 레시피·브리지는 [docs 전용 예시](examples/submissions/README.md)에 있다. Mbed TLS는 SDK 예시일 뿐 이번 3개 제출물이나 20조합의 일부가 아니다. 임시 경로에서만 동작하던 복사본은 이관하지 않았다. |
| `experiments/20261126T0132Z/gnutls/upstream/` 및 시험 입력 | 원본 배포 아카이브를 독립 입력 묶음에도 복사했다. wolfSSL·OpenSSL·JSON을 포함한 정확한 파일명과 지문은 [검증 드라이버](../tools/validation/build-matrix.sh), 취득·재현 명령은 [검증 보고](scenario-validation.ko.md) 참조. 제품에서 자동 벤더 다운로드·레시피 선택을 추가하지 않았다. |

### 역사 자료와 복원

이 머신의 개인 보관소는 `~/.local/share/turtle/archive/2026-11-26`(이하 **A**)이다. **연구 원본은 `A/home/TURTLE-build-study/`**에서 바로 읽을 수 있다. 예전 홈 경로에는 링크를 남기지 않았다. 별도 백업은 `A/home/TURTLE-validation-20261126/backup/`에 있다. `research.tar`에는 연구 폴더 전체, `historical-jobs.tar`에는 정리 전 제품의 `out/`, `outputs/`, `build/` 전체가 있다. 디렉터리 구조와 심볼릭 링크를 그대로 보존했다. 역사적 job의 링크 25개는 옛 연구 폴더의 절대경로를 가리킨다. 이 링크가 필요한 과거 작업은 원래 경로를 복원한 뒤 사용한다. 현행 빌드·검증에는 필요하지 않다. 과거 작업이 제품의 옛 `out/`을 가리키는 observer 링크 3개는 `sh "$A/read-legacy-observer.sh"`로 홈을 복원하지 않고 읽기 전용으로 검산할 수 있다. 인증서 시험용 키가 있을 수 있어 배포용 자료가 아니다. 개별 원본 내용은 링크를 따라가지 않고도 꺼낼 수 있다.

```sh
A="$HOME/.local/share/turtle/archive/2026-11-26"
cd "$A/home/TURTLE-validation-20261126/backup"
sha256sum -c SHA256SUMS
tar -xOf research.tar TURTLE-build-study/evidence/wrong-config-header-control.log
tar -xOf research.tar TURTLE-build-study/experiments/20261126T0146Z/verified-connections.tsv | head
# 전체 복원은 별도의 빈 디렉터리에 한정: tar -xf research.tar -C "$empty"
```

보존 시 두 아카이브를 원본과 `tar --compare`로 비교하고 역사 대조 로그와 연결 TSV를 스트림으로 추출해 원본과 바이트 단위로 비교했다. 원본별 목록(`*-files.txt.gz`), 대조 로그(`*-compare.log`), 읽기/해시 검산(`verified.txt`)도 같은 곳에 있다. 보관 폴더와 경로 복원 안내는 `A/README.ko.md`, 경로 변경 전 발행 문서는 `A/published/docs/`에 있다. 연구 원본 이동 전후에 `research.tar`와 다시 대조한 기록은 `A/receipts/study-relocation/`에 있다. `~/TURTLE-paper`와 기존 인계 기록은 변경하지 않았다.
