execute_process(
  COMMAND "${TURTLE_BINARY}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error
  TIMEOUT 5)

if(NOT "${result}" STREQUAL "1")
  message(FATAL_ERROR "Expected an invalid run to exit with 1 (${result}):\n${output}\n${error}")
endif()

if(NOT output MATCHES "run is invalid" OR NOT output MATCHES "a role failed")
  message(FATAL_ERROR "Verification failure was not reported:\n${output}")
endif()

if(output MATCHES "measurement 2/2" OR output MATCHES "all roles finished")
  message(FATAL_ERROR "Director continued after a failed measurement:\n${output}")
endif()
