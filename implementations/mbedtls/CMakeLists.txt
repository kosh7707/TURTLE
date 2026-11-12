cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(turtle_mbedtls_adapter LANGUAGES CXX)
endif()

if(NOT DEFINED TURTLE_DEPS_ROOT)
  set(TURTLE_DEPS_ROOT "$ENV{TURTLE_DEPS_ROOT}" CACHE PATH
      "Root containing locally built TURTLE dependencies")
  if(NOT TURTLE_DEPS_ROOT)
    message(FATAL_ERROR "Set TURTLE_DEPS_ROOT to the dependency cache root")
  endif()
endif()

set(_mbedtls_hints)
if(TURTLE_DEPS_ROOT)
  list(APPEND _mbedtls_hints
       "${TURTLE_DEPS_ROOT}/install/mbedtls-3.6.4-pic"
       "${TURTLE_DEPS_ROOT}/install/mbedtls-3.6.4"
       "${TURTLE_DEPS_ROOT}/mbedtls")
endif()
find_package(MbedTLS 3.6.4 CONFIG REQUIRED PATHS ${_mbedtls_hints} NO_DEFAULT_PATH)

add_library(turtle_adapter_mbedtls MODULE mbedtls.cpp adapter.hpp)
target_compile_features(turtle_adapter_mbedtls PRIVATE cxx_std_20)
get_filename_component(_turtle_root "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
target_include_directories(turtle_adapter_mbedtls PRIVATE "${_turtle_root}/include")
target_link_libraries(turtle_adapter_mbedtls PRIVATE
                      MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
target_compile_definitions(turtle_adapter_mbedtls PRIVATE MBEDTLS_PLATFORM_MEMORY)
target_compile_options(turtle_adapter_mbedtls PRIVATE
                       -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
set_target_properties(turtle_adapter_mbedtls PROPERTIES
  PREFIX ""
  OUTPUT_NAME "mbedtls"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/adapters")


file(SHA256 "${CMAKE_CURRENT_LIST_DIR}/instrumentation.patch" _turtle_patch_hash)
include(../common/patch-provenance.cmake)
turtle_check_patch_manifest(mbedtls "${_turtle_patch_hash}")
target_compile_definitions(turtle_adapter_mbedtls PRIVATE TURTLE_PATCH_SHA256="${_turtle_patch_hash}")

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/instrumentation.patch")
