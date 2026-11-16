# 연구 기능 실행

모든 기능은 공통 메시지 실행기와 사건 계약을 사용합니다. 실제 구현과 관측된 동작만 기법의 성공으로 기록합니다. 논문 성능 수치나 다른 최적화 기법을 재현했다고 주장하지 않습니다.

## ML-KEM

`mlkem-c`와 `mlkem-avx2`는 같은 wolfSSL 커밋과 경계 패치에서 빌드합니다. 두 ML-KEM 번역 단위에만 native C·AVX2 dispatch 조건이 다르며 공통 어셈블리·CPUID 지원은 같습니다. TLS는 ML-KEM-768 키 생성·캡슐화·역캡슐화의 실제 native 함수를 사용합니다. 연결 결과에 완료한 연산 수와 실제 최적화 분기 횟수가 있습니다. 내부 분기의 횟수는 최상위 KEM 호출 횟수와 같다고 가정하지 않습니다.

```sh
python3 scripts/run.py --client mlkem-avx2 --server mlkem-avx2 --group ML-KEM-768 \
  --mutual-auth --depth white-box --stream --output results/mlkem
python3 scripts/verify-mlkem-build.py --output results/mlkem-objects.json
```

오브젝트 검사는 디버그 정보만 제거하고 코드·상수 데이터의 차이가 `wc_mlkem.c`와 `wc_mlkem_poly.c` 두 파일에만 있는지 확인합니다. 원본·정규화 오브젝트의 목적과 빌드 옵션을 함께 읽습니다. CPU가 해당 dispatch를 실행하지 않았다면 최적화 기법 실행 증거로 사용할 수 없습니다.

## BiTHaC

원본은 RWTH-SPICe/BiTHaC의 고정 커밋입니다. `bithac-baseline`과 `bithac-cached`는 같은 기반이며 cached에서 저자 코드의 CI·SSC를 켭니다. 전역 CI 캐시와 peer index를 컨텍스트 소유로 옮겼고, handshake 종료에서 하던 캐시 갱신을 명시적인 FINISH 전환에 연결했습니다. 캐시와 인증 상태를 연결 사이에 재사용하지만 TLS 세션을 재개하지 않습니다.

```sh
python3 scripts/run.py --client bithac-cached --server bithac-cached \
  --connections 3 --mutual-auth --depth white-box --stream --allocations \
  --output results/bithac
```

첫 연결의 캐시 삽입, 뒤 연결의 cache hit, 실제 Certificate·CertificateRequest 바이트와 검증 성공을 함께 확인합니다. 결과에는 CI 인증서·요청과 SSC cache hit를 따로 기록합니다. 최초 컨텍스트 준비와 연결별 준비·처리 비용을 분리하고, 캐시 저장 공간은 컨텍스트의 실제 보유 항목으로 계산합니다. 저자 코드의 small certificate cache 최적화는 켜지 않습니다. 새 독립 프로세스에서 첫 연결은 다시 빈 기법 캐시로 시작합니다.

## 합성 객체 MockCA

MockCA는 고정 바이트 객체를 반환하는 독립 조회 엔드포인트입니다. 실제 인증서 발급, 인증서 대체, OCSP·ACME 구현이 아닙니다. TLS 인증서는 기존 시험 PKI를 그대로 사용합니다.

```sh
python3 scripts/mockca.py OBJECT.bin results/mockca --port 44332
```

엔드포인트 명세에 lookup_sha256·lookup_size·lookup_address·lookup_port를 지정하면 컨텍스트 준비 전에 조회→SHA-256 검증→소유 캐시 삽입을 마친 뒤 TLS를 실행합니다. `lookup_snapshot`을 지정하면 같은 객체의 고정 로컬 저장본을 읽어 검증·삽입합니다. 빈 캐시의 원격 조회와 고정 저장본 준비를 같은 조건으로 합치지 않습니다. 양쪽 역할에 각각 설정할 수 있습니다. 클라이언트·서버의 lookup 비용과 서비스의 조회 처리 비용은 독립 시계·역할로 기록합니다. 서비스는 요청의 run_id와 요청 역할을 보존합니다.

공통 실행기는 조회 완료 후 추가 TLS 루프 없이 정상 시나리오를 실행합니다. 조회 객체는 컨텍스트 수명 동안 보유하며 반복 연결에서 준비 비용을 복제하지 않습니다. `network.py --object`로 별도의 조회 흐름·netem·pcap 증거도 수집할 수 있습니다.

네트워크와 CPU 표본은 각각 [네트워크 관측](../analysis/network.md), [CPU 표본](../analysis/cpu-profiling.md)을 따릅니다. 환경 때문에 수집할 수 없는 기능은 TLS 성공과 별도로 미지원·미수집·누락으로 표시합니다.

## 상대 구현체를 고정한 비교

`examples/message/mlkem-study.json`과 `bithac-study.json`은 한쪽 상대 바이너리를 고정하고 다른 쪽 구현을 바꾸는 배치를 제공합니다. BiTHaC의 baseline/cached 교차 연결도 정상 전체 인증으로 검증했습니다. 이 배치에서 역할별·연결 위치별 컨텍스트 부트스트랩 비교를 만들 수 있습니다. 양쪽을 동시에 바꾸는 self-pair의 결과와 구별합니다.
