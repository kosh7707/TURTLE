cmake_minimum_required(VERSION 3.20)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(turtle_openssl_adapter LANGUAGES C CXX)
    find_package(TURTLE CONFIG REQUIRED)
endif()

# 이 디렉터리를 명시적으로 선택했을 때만 OpenSSL을 찾는다.
# FindOpenSSL의 정적 의존성 조회도 선택한 설치의 pkg-config를 사용한다.
set(turtle_saved_pkg_config_path "$ENV{PKG_CONFIG_PATH}")
if(OPENSSL_ROOT_DIR)
    set(ENV{PKG_CONFIG_PATH} "${OPENSSL_ROOT_DIR}/lib/pkgconfig:${OPENSSL_ROOT_DIR}/lib64/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endif()
find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL Crypto)
set(ENV{PKG_CONFIG_PATH} "${turtle_saved_pkg_config_path}")
set(TURTLE_OPENSSL_CONFIG_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/configure.cpp"
    CACHE FILEPATH "OpenSSL context configuration source")

add_library(turtle-openssl_implementation STATIC
    implementation.cpp "${TURTLE_OPENSSL_CONFIG_SOURCE}")
target_link_libraries(turtle-openssl_implementation PRIVATE
    turtle::contract OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(turtle-openssl_implementation PRIVATE cxx_std_20)
target_include_directories(turtle-openssl_implementation PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(turtle-openssl main.cpp)
set_target_properties(turtle-openssl PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_libraries(turtle-openssl PRIVATE turtle::endpoint turtle-openssl_implementation)
foreach(target IN ITEMS turtle-openssl turtle-openssl_implementation)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF)
endforeach()
