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

# Compile the native call path once. Only the target's configuration is
# replaceable: changing it must never change the default opposite peer.
add_library(turtle-openssl_driver OBJECT implementation.cpp)
target_compile_features(turtle-openssl_driver PUBLIC cxx_std_20)
target_link_libraries(turtle-openssl_driver PUBLIC turtle::endpoint OpenSSL::SSL OpenSSL::Crypto)
function(turtle_openssl_program name configuration directory)
    add_executable(${name} main.cpp "${configuration}")
    target_link_libraries(${name} PRIVATE turtle-openssl_driver)
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${directory}" CXX_EXTENSIONS OFF)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
endfunction()
target_compile_options(turtle-openssl_driver PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(turtle-openssl_driver PROPERTIES CXX_EXTENSIONS OFF)
turtle_openssl_program(turtle-openssl "${TURTLE_OPENSSL_CONFIG_SOURCE}" "${CMAKE_BINARY_DIR}")
if(NOT TURTLE_REFERENCE_RUNTIME_DIR)
    set(TURTLE_REFERENCE_RUNTIME_DIR "${CMAKE_BINARY_DIR}")
endif()
turtle_openssl_program(turtle-reference "${CMAKE_CURRENT_SOURCE_DIR}/configure.cpp" "${TURTLE_REFERENCE_RUNTIME_DIR}")
