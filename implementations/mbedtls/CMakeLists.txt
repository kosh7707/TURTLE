cmake_minimum_required(VERSION 3.20)

set(TURTLE_DEPS_ROOT "$ENV{TURTLE_DEPS_ROOT}" CACHE PATH
    "Root containing locally built TURTLE dependencies")

set(_mbedtls_hints)
if(TURTLE_DEPS_ROOT)
  list(APPEND _mbedtls_hints
       "${TURTLE_DEPS_ROOT}/install/mbedtls-3.6.4-pic"
       "${TURTLE_DEPS_ROOT}/install/mbedtls-3.6.4"
       "${TURTLE_DEPS_ROOT}/mbedtls")
endif()
find_package(MbedTLS 3.6.4 CONFIG REQUIRED HINTS ${_mbedtls_hints})

add_library(turtle_adapter_mbedtls MODULE mbedtls.cpp)
target_compile_features(turtle_adapter_mbedtls PRIVATE cxx_std_20)
get_filename_component(_turtle_root "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
target_include_directories(turtle_adapter_mbedtls PRIVATE "${_turtle_root}/include")
target_link_libraries(turtle_adapter_mbedtls PRIVATE
                      MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
set_target_properties(turtle_adapter_mbedtls PROPERTIES
  PREFIX ""
  OUTPUT_NAME "mbedtls"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/adapters")

