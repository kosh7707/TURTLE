cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(turtle_wolfssl_adapter LANGUAGES CXX)
endif()
if(NOT DEFINED TURTLE_SOURCE_ROOT)
  set(TURTLE_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." CACHE PATH
      "TURTLE source tree containing include/turtle/adapter.hpp")
endif()

set(TURTLE_DEPS_ROOT "$ENV{TURTLE_DEPS_ROOT}" CACHE PATH
    "Root of TURTLE's locally built TLS dependencies")
if(NOT TURTLE_DEPS_ROOT)
  message(FATAL_ERROR "Set TURTLE_DEPS_ROOT to the dependency cache root")
endif()

set(_wolfssl_prefix "${TURTLE_DEPS_ROOT}/install/wolfssl-5.8.2-stable")
find_package(wolfssl CONFIG REQUIRED
             PATHS "${_wolfssl_prefix}/lib/cmake/wolfssl" NO_DEFAULT_PATH)

add_library(turtle_adapter_wolfssl MODULE wolfssl_adapter.cpp)
target_compile_features(turtle_adapter_wolfssl PRIVATE cxx_std_20)
target_include_directories(turtle_adapter_wolfssl PRIVATE
                           "${TURTLE_SOURCE_ROOT}/include")
target_link_libraries(turtle_adapter_wolfssl PRIVATE wolfssl::wolfssl)
target_compile_definitions(turtle_adapter_wolfssl PRIVATE
                           HAVE_SECRET_CALLBACK SHOW_SECRETS)
target_compile_options(turtle_adapter_wolfssl PRIVATE
                       -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
set_target_properties(turtle_adapter_wolfssl PROPERTIES
  PREFIX ""
  OUTPUT_NAME "wolfssl"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/adapters")

