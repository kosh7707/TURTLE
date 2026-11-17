# 독립 빌드·실행 검증

의존성을 준비한 뒤 현재 소스만 새 디렉터리에 복사하고 Python·libpython·tools·외부 작업 공간·외부 네트워크 없이 구성·빌드·TLS 실행·분석이 가능한지 확인한다.

선택적 도구는 격리 환경 밖에서 다음을 실행한다.

```sh
python3 tools/check_independence.py out/independent \
  --framework-prefix .deps/native \
  --openssl-prefix .deps/openssl-3.5.9/install \
  --wolfssl-prefix .deps/wolfssl-5.9.4/install
```

도구는 CMake, `src/`, `include/`, 구현체와 C/C++ 시험만 복사한다. bubblewrap 안에서는 `/home`이 비어 있고 네트워크가 분리된다. Python 실행 파일과 libpython 공유 라이브러리를 사용할 수 없도록 가린다. `tools/`와 Python 패키지는 복사하지 않는다.

격리 안의 명령은 CMake·Ninja·CTest·네이티브 TURTLE과 준비한 라이브러리만 사용한다. C 계약, 외부 빌드 등록, 결정적 프레임·패킷·구간 분석, 실제 두 라이브러리 연결과 설치한 CLI의 재분석을 수행한다. 각 명령·반환 코드·로그를 `verification.json`에 남긴다. perf의 연결 라이브러리도 확인한다.

실제 netem·PMU 시험은 별도의 권한 있는 환경에서 수행한다. 사용자 네임스페이스의 root를 호스트의 perf 권한과 같은 것으로 취급하지 않는다. 이 검증과 ARM64 교차 빌드·실제 보드 검증도 구별한다. 결과는 [검증 기록](validation.md)에 모은다.

`--privileged-tests`를 root에서 사용하면 사용자 네임스페이스로 권한을 바꾸지 않고 파일·프로세스·네트워크 격리를 유지하면서 netem·PMU 시험도 포함한다. 필요한 `/sys` 조회만 읽기 전용으로 제공한다. Python 실행 파일과 libpython은 이 경로에서도 가려진다.
