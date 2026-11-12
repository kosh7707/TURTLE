# 같은 ML-KEM-768 구현의 C·AVX2 비교

wolfSSL 5.8.2-stable의 [고정 커밋](https://github.com/wolfSSL/wolfssl/tree/decea12e223869c8f8f3ab5a53dc90b69f436eb2)에서 `mlkem-c`와 `mlkem-avx2`를 만듭니다. 두 구현 모두 인증서 기반 TLS 1.3 전체 핸드셰이크, ML-KEM-768 키 교환, ECDSA P-256 인증, AES-128-GCM/SHA-256을 사용합니다. 원래 P-256 ECDHE 프로필과 다른 실험이며 `technique=mlkem768-tls13`, `scenario_name=research-tls13`으로 기록합니다.

이 비교는 upstream ML-KEM의 C·AVX2 실행 경로 비교입니다. 후보 논문 *Faster Post-Quantum TLS 1.3 Based on ML-KEM*의 AVX-512 구현이나 저자 성능 수치를 재현한 결과로 표시하지 않습니다. 채택한 논문 기법 BiTHaC의 출처는 [별도 문서](research-reproduction.md)에 있습니다.

## 바뀌는 조건과 실행 증거

`scripts/build-mlkem.sh`는 동일 원본과 계측 패치를 두 번 빌드합니다. `wc_mlkem.c`와 `wc_mlkem_poly.c`에만 `USE_INTEL_SPEEDUP`, `HAVE_INTEL_AVX1`, `HAVE_INTEL_AVX2`를 적용하고, C 구현에만 `WC_MLKEM_NO_ASM`을 추가합니다. 다른 암호 구현 전체의 가속 설정을 바꾸지 않습니다. 두 빌드 모두 동일한 ML-KEM·SHA3 어셈블리 오브젝트를 포함하지만 C 구현은 해당 ML-KEM 분기를 호출하지 않습니다.

`scripts/verify-mlkem-build.py`가 라이브러리 오브젝트 41개를 비교합니다. 두 ML-KEM C 오브젝트만 다르고 나머지 39개가 SHA-256까지 같습니다. 원본 커밋·컴파일 조건·패치 해시는 `.deps/manifests/mlkem-*.txt`, `mlkem-instrumentation.sha256`, `mlkem-object-comparison.json`에 남습니다. 어댑터 선언에도 원본·패치·구현 구분을 기록합니다.

AVX2 경로는 다항식 연산뿐 아니라 ML-KEM 내부 SHA3, 표현 변환과 임시 메모리 처리도 바꿉니다. 전체 KEM API 시간과 내부 다항식 시간은 중첩 구간이므로 더하지 않습니다. API 구간에는 upstream 난수 생성 등 해당 호출의 전체 작업이 포함됩니다. 공개 계측은 다음 실제 위치를 사용합니다.

| 사건 | 관측 위치 | 역할 |
|---|---|---|
| `kem_keygen` | TLS 경로의 `wc_MlKemKey_MakeKey` 호출 | 클라이언트 |
| `kem_encapsulate` | TLS 경로의 `wc_MlKemKey_Encapsulate` 호출 | 서버 |
| `kem_decapsulate` | TLS 경로의 `wc_MlKemKey_Decapsulate` 호출 | 클라이언트 |
| `kem_polynomial_keygen` | 실제 C 또는 AVX2 다항식 키 생성 분기 | 클라이언트 |
| `kem_polynomial_encapsulate` | 실제 C 또는 AVX2 캡슐화 분기 | 서버, 클라이언트 decapsulation의 재암호화 |
| `kem_polynomial_decapsulate` | 실제 C 또는 AVX2 복호화 분기 | 클라이언트 |

키 객체가 비소유 콜백·연결 인자를 보관하며 전역 계측기를 추가하지 않습니다. 다항식 사건의 `message_type=1`은 실제 C 분기, `2`는 실제 AVX2 분기입니다. CPU 기능이나 모듈 로드만으로 경로 실행을 인정하지 않습니다. AVX2 미지원 CPU가 C 분기로 내려가면 추적 검증은 실패로 남깁니다. 현재 빌드 쌍은 x86_64용이며 ARM 최적화 비교 쌍은 별도 작업입니다.

컴파일에는 upstream 기본 ML-KEM 파라미터 집합을 유지하고 TLS 그룹 목록만 ML-KEM-768 하나로 제한합니다. 처음에 512·1024를 컴파일에서 제외했을 때 upstream 그룹 switch의 조건부 `break` 때문에 그룹 설정이 실패했습니다. 원본 분기를 고치는 대신 기본 파라미터 빌드를 유지했습니다. 실패는 `artifacts/mlkem-debug-1/`에 남아 있습니다. 실제 wire 그룹 513과 ClientHello 키 공유 하나, HRR·재개 없음은 해독 결과로 확인합니다.

## 실행과 재생성

```sh
JOBS=4 scripts/build-mlkem.sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DTURTLE_ADAPTER_LINKAGE=module -DTURTLE_BUILD_MODULES=ON -DTURTLE_WITH_OPENSSL=ON \
  -DTURTLE_WITH_WOLFSSL=ON -DTURTLE_WITH_MBEDTLS=ON \
  -DTURTLE_WITH_BITHAC=ON -DTURTLE_WITH_MLKEM=ON
cmake --build build --parallel 4
python3 scripts/mlkem-study.py run --build build --pki pki/default \
  --samples 3 --no-affinity --output results/mlkem-pilot
python3 scripts/mlkem-study.py analyze --build build --output results/mlkem-pilot
```

기준 `C/C`, 클라이언트만 AVX2, 서버만 AVX2의 세 조건입니다. 한쪽 역할을 비교할 때 상대 엔드포인트는 C로 고정합니다. 시간·추적·메모리는 별도 실행이며 컨텍스트당 연결 1개, 워밍업 0회입니다. 저장한 seed에 따라 실행 순서를 섞고 원자료·로그·`mlkem-summary.json`·`mlkem-table.csv`를 보존합니다. 실패 또는 필수 호출 경로 누락을 성공 표본으로 대체하지 않습니다.

정상 벡터는 같은 upstream `tests/api/test_mlkem.c`의 입력·기대 출력에서 추출했습니다. 두 구현의 키 생성·캡슐화 기대 해시와 정상 decapsulation을 확인하고 벡터 라이선스를 함께 보존했습니다. 실제 TLS 회귀는 2×2 구현 조합 × 네 시나리오 × 두 정책 × 두 인증으로 64개 실행, 각각 새 TCP 두 연결입니다. `artifacts/mlkem-matrix-1/verification.json`에 결과가 있습니다.

`artifacts/mlkem-pilot-1/`은 3모드 × 3표본 × 3조건 × 2역할의 54행입니다. 추적 실행에서는 모든 예상 C·AVX2 분기와 API 호출을 확인했습니다. 이는 WSL에서 실행·관측·표 재생성을 검증한 자료이며 성능 우위의 결론이나 본 실험의 반복 횟수 결정이 아닙니다.
