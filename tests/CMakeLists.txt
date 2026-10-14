cmake_minimum_required(VERSION 3.20)
project(turtle_tests CXX)

# Tests are a separate project with their own build tree; the framework
# sources know nothing about them.
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. turtle)

enable_testing()

add_test(NAME lifecycle COMMAND turtle)
set_tests_properties(lifecycle PROPERTIES
  PASS_REGULAR_EXPRESSION "all roles finished"
  TIMEOUT 10)

add_test(NAME lifecycle_verification_failed
  COMMAND ${CMAKE_COMMAND}
    -DTURTLE_BINARY=$<TARGET_FILE:turtle>
    -P ${CMAKE_CURRENT_SOURCE_DIR}/check_failed_measurement.cmake)
set_tests_properties(lifecycle_verification_failed PROPERTIES
  ENVIRONMENT TURTLE_MOCK_VERIFY_FAIL=1
  TIMEOUT 10)

# A test-only implementation checks process and resource boundaries without
# adding test behavior to the framework or the public mock implementation.
add_executable(turtle_lifecycle_probe
  ../src/main.cpp
  ../src/transport/tcp.cpp
  lifecycle_probe.cpp)
target_compile_features(turtle_lifecycle_probe PRIVATE cxx_std_20)
target_include_directories(turtle_lifecycle_probe PRIVATE ../include ../src)

add_test(NAME lifecycle_fresh_processes
  COMMAND ${CMAKE_COMMAND}
    -DTURTLE_BINARY=$<TARGET_FILE:turtle_lifecycle_probe>
    -P ${CMAKE_CURRENT_SOURCE_DIR}/check_measurements.cmake)
set_tests_properties(lifecycle_fresh_processes PROPERTIES TIMEOUT 10)

add_test(NAME lifecycle_prepared_before_isolation
  COMMAND ${CMAKE_COMMAND}
    -DTURTLE_BINARY=$<TARGET_FILE:turtle_lifecycle_probe>
    -P ${CMAKE_CURRENT_SOURCE_DIR}/check_measurements.cmake)
set_tests_properties(lifecycle_prepared_before_isolation PROPERTIES
  ENVIRONMENT TURTLE_PROBE_CHECK_LIMITS=1
  TIMEOUT 10)

add_test(NAME lifecycle_failure_stops_measurements
  COMMAND ${CMAKE_COMMAND}
    -DTURTLE_BINARY=$<TARGET_FILE:turtle_lifecycle_probe>
    -P ${CMAKE_CURRENT_SOURCE_DIR}/check_failed_measurement.cmake)
set_tests_properties(lifecycle_failure_stops_measurements PROPERTIES
  ENVIRONMENT TURTLE_PROBE_VERIFY_FAIL=1
  TIMEOUT 10)
