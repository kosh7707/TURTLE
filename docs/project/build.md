# 개발자가 가져온 구현체를 빌드에 포함하는 계약

TURTLE 코어는 어떤 TLS 구현체를 사용할지 결정하지 않습니다. 기본 빌드는 코어만 생성하며, 개발자가 선택한 디렉터리의 `CMakeLists.txt`를 별도 빌드 디렉터리에 포함합니다. 그 파일이 소스·헤더·컴파일 옵션·라이브러리·의존성과 실제 빌드 방법을 정의합니다.

빌드 등록 자체는 일반 CMake 대상과 개발자가 작성한 실행 파일을 받아들입니다. 공통 계측 실행에는 `turtle_implementation` 함수표와 `turtle_endpoint_main`을 사용합니다. 빌드 연결의 성공과 실제 TLS·계측 실행의 성공은 별도로 검증합니다.

핸드셰이크 결과에는 정규화한 버전·재개 여부와 `profile`을 채웁니다. 네 구간 상세 계측을 지원하는 설정은 `TURTLE_PROFILE_SERVER_AUTH_1RTT`를 선언합니다. 인증서 기반 서버 인증이고 클라이언트 인증·재개·0-RTT·HRR·핸드셰이크 호출 중 티켓·응용 데이터가 없는 조건입니다. 이를 보장하지 않는 연산은 `TURTLE_PROFILE_UNSPECIFIED`를 반환합니다. 세부 조건과 비용의 포함 범위는 [구간 설계](handshake-phases.md)에 있습니다. 제공한 예제의 configure 소스나 연산을 바꿀 때 이 선언도 현재 설정에 맞춰야 합니다.

## 소스와 빌드의 위치

```text
/work/TURTLE/                   공통 소스와 헤더
/work/my-tls/                   연구자의 원본 TLS 소스
/work/my-benchmark/
    CMakeLists.txt              사용할 소스·라이브러리와 실행 파일을 정의
    main.cpp                   연구자의 실행 코드
/work/build/                   모든 빌드 산출물
```

```sh
cmake -S /work/TURTLE -B /work/build -G Ninja \
  -DTURTLE_IMPLEMENTATION_DIRS=/work/my-benchmark
cmake --build /work/build
```

여러 디렉터리는 `-DTURTLE_IMPLEMENTATION_DIRS="/work/a;/work/b"`처럼 지정합니다. 상대 경로는 TURTLE 소스 루트를 기준으로 해석합니다. 디렉터리 이름이 같아도 전체 경로를 기준으로 산출물 디렉터리를 구분합니다. 각 빌드 정의 안의 CMake 대상 이름은 개발자가 충돌 없이 정합니다.

소스를 TURTLE 안으로 복사하거나 모든 구현체의 빌드 체계를 변환할 필요는 없습니다. CMake의 `add_subdirectory`는 소스 위치와 산출물 위치를 따로 지정할 수 있습니다. [CMake 문서](https://cmake.org/cmake/help/latest/command/add_subdirectory.html)

## CMake로 빌드하는 소스

원래 프로젝트가 제공하는 라이브러리 대상을 사용합니다. 아래의 `research_tls`는 해당 프로젝트가 실제로 정의한 대상 이름으로 바꿉니다.

```cmake
add_subdirectory("/work/my-tls" "${CMAKE_CURRENT_BINARY_DIR}/tls")
add_executable(research-run main.cpp)
target_link_libraries(research-run PRIVATE turtle::core research_tls)
```

소수의 C/C++ 소스만 있는 구현체는 같은 파일에서 `add_library(research_tls STATIC ...)`로 직접 정의해도 됩니다. 공개 헤더 경로와 필요한 컴파일 정의는 해당 대상에 붙입니다. TURTLE 코어의 C++20 설정이나 경고 옵션을 외부 TLS 소스 전체에 전역으로 적용하지 않습니다.

## 이미 빌드한 라이브러리

프로젝트가 CMake 패키지를 제공하면 `find_package`로 가져온 대상을 사용합니다. 패키지가 없다면 헤더와 실제 라이브러리 파일을 명시합니다.

```cmake
add_library(research_tls STATIC IMPORTED)
set_target_properties(research_tls PROPERTIES
    IMPORTED_LOCATION "/work/my-tls/install/lib/libresearch.a"
    INTERFACE_INCLUDE_DIRECTORIES "/work/my-tls/install/include")
add_executable(research-run main.cpp)
target_link_libraries(research-run PRIVATE turtle::core research_tls)
```

공유 라이브러리는 `SHARED IMPORTED`로 정의합니다. 필요한 컴파일 정의와 추가 링크 의존성도 대상의 인터페이스에 기록합니다. TURTLE은 라이브러리 이름만으로 이를 추측하지 않습니다. CMake의 `IMPORTED` 대상은 이미 존재하는 파일을 가리키며 그 파일을 다시 빌드하지 않습니다. [CMake 가져오기 문서](https://cmake.org/cmake/help/latest/guide/importing-exporting/index.html)

## Make·Configure 등 다른 방식으로 빌드하는 소스

`ExternalProject_Add`에서 프로젝트의 원래 구성·빌드·설치 명령을 실행하고 결과 라이브러리를 `IMPORTED` 대상으로 연결합니다. 다음은 별도 빌드 디렉터리에서 실행되는 Makefile을 가진 프로젝트의 예입니다. 실제 프로젝트에 맞게 명령과 산출물 위치를 지정해야 합니다.

```cmake
include(ExternalProject)
find_program(MAKE_EXECUTABLE NAMES gmake make REQUIRED)

ExternalProject_Add(research_build
    SOURCE_DIR "/work/my-tls"
    BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/native"
    DOWNLOAD_COMMAND "" UPDATE_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND "${MAKE_EXECUTABLE}" -f <SOURCE_DIR>/Makefile
                  SOURCE_DIR=<SOURCE_DIR>
                  CC=${CMAKE_C_COMPILER} AR=${CMAKE_AR}
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS <BINARY_DIR>/libresearch.a)

add_library(research_tls STATIC IMPORTED)
set_target_properties(research_tls PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/native/libresearch.a"
    INTERFACE_INCLUDE_DIRECTORIES "/work/my-tls/include")
add_dependencies(research_tls research_build)

add_executable(research-run main.cpp)
target_link_libraries(research-run PRIVATE turtle::core research_tls)
```

Configure가 필요한 프로젝트는 `CONFIGURE_COMMAND`를 채우고, 설치된 헤더와 라이브러리를 사용할 경우 설치 명령과 산출물 경로도 지정합니다. 생성되는 헤더가 있다면 해당 대상의 빌드 의존성과 헤더 위치도 함께 선언합니다. `BUILD_BYPRODUCTS`는 Ninja가 라이브러리 생성 작업과 링크 작업의 관계를 알 수 있게 합니다. 다운로드 명령은 사용하지 않으며 가져온 로컬 소스를 사용합니다. [ExternalProject 문서](https://cmake.org/cmake/help/latest/module/ExternalProject.html)

## 개발자의 프로젝트 안에 TURTLE을 넣는 경우

개발자의 프로젝트를 최상위로 유지할 수도 있습니다.

```cmake
cmake_minimum_required(VERSION 3.20)
project(my_benchmark LANGUAGES C CXX)
add_subdirectory("/work/TURTLE" "${CMAKE_BINARY_DIR}/turtle")
add_subdirectory("/work/my-tls" "${CMAKE_BINARY_DIR}/tls")
add_executable(research-run main.cpp)
target_link_libraries(research-run PRIVATE turtle::core research_tls)
```

`turtle::core`는 코어 정적 라이브러리와 공개 헤더를 제공합니다. `turtle::contract`는 C 공개 헤더만 제공합니다. `turtle::endpoint`는 공통 CLI 진입점과 코어를 연결합니다. 코어의 `src/` 헤더는 외부 대상에 전파하지 않으며 OpenSSL·wolfSSL 예제도 내부 헤더를 사용하지 않습니다.

## 검증 범위

`tests/registration.cmake`는 코어 단독 빌드, 외부 CMake 소스, 별도 설치한 정적 라이브러리, Make 소스, 개발자 프로젝트 안의 TURTLE 포함을 실제 컴파일·링크·실행으로 확인합니다. 모든 경우에서 OpenSSL 탐색을 비활성화하고, 공백이 있는 경로와 이름이 같은 외부 디렉터리도 사용합니다. 시험용 C/C++ 부품은 빌드 경로를 확인하기 위한 것이며 TLS 기능을 흉내 내지 않습니다.

실제 TLS 검증은 별도로 선택한 OpenSSL·wolfSSL 예제의 동종·교차 연결로 수행합니다. 다른 TLS 라이브러리와 임의의 외부 빌드 정의가 모두 검증됐다고 주장하지 않습니다. 개발자가 제공할 빌드 명령, 의존성, 산출물과 컴파일 옵션을 명확하게 선언할 수 있는 접점을 제공하는 것이 이 계약의 범위입니다.

## 공통 엔드포인트로 실행하는 외부 구현체

외부 디렉터리에 아래와 같은 빌드 정의를 둡니다. `operations.c`는 준비·핸드셰이크·응용 송수신·해제를 구현하고 `research_implementation()`에서 함수표를 반환하는 개발자 코드입니다. 이 이름은 개발자가 정하며 TURTLE이 전역으로 찾지 않습니다.

```cmake
add_library(research_operations STATIC operations.c)
target_link_libraries(research_operations PRIVATE turtle::contract research_tls)
add_executable(research-endpoint main.c)
target_link_libraries(research-endpoint PRIVATE turtle::endpoint research_operations)
```

```c
#include <turtle/endpoint.h>
extern turtle_implementation research_implementation(void);
int main(int argc, char** argv) {
    turtle_implementation api = research_implementation();
    return turtle_endpoint_main(&api, argc, argv);
}
```

CMake는 `turtle::endpoint`의 C++ 링크 의존성을 이어 줍니다. 함수표 자체와 main은 C로 작성할 수 있습니다. 같은 공개 API를 사용하는 연구자는 기존 OpenSSL·wolfSSL 연결 소스를 재사용하고 설정 소스나 TLS 라이브러리 빌드를 바꿀 수도 있습니다. 준비 함수의 인자는 `--` 뒤 문자열 그대로이며 공통 코드가 인증서·Provider 경로를 고정하지 않습니다.

외부 실행 파일을 비교 명세의 `client.binary`·`server.binary`로 지정하면 같은 실행 도구와 분석기를 사용합니다. 별도 바이너리 플러그인 ABI, 코어의 라이브러리 이름 분기, 내부 헤더 포함은 필요하지 않습니다. `tests/registration.cmake`는 저장소 밖 C 소스가 이 공개 헤더로 공통 진입점을 링크하는 경로도 검사합니다. 이 작은 링크 시험을 실제 TLS 성공으로 세지는 않습니다.

선택한 OpenSSL 설치의 정적 의존성은 해당 설치의 `lib/pkgconfig` 또는 `lib64/pkgconfig`에서 읽습니다. `OPENSSL_ROOT_DIR`을 바꾸면 CMake 캐시의 이전 탐색 결과가 남을 수 있으므로 새 빌드 디렉터리를 사용합니다. 현재 wolfSSL 예제의 IMPORTED 대상은 지정한 헤더·라이브러리와 Threads·수학 라이브러리를 연결합니다. 다른 wolfSSL 빌드가 추가 의존성을 요구하면 개발자의 빌드 정의에 명시해야 합니다.
