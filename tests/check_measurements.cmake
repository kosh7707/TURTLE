execute_process(
  COMMAND "${TURTLE_BINARY}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error
  TIMEOUT 5)

if(NOT "${result}" STREQUAL "0")
  message(FATAL_ERROR "Measurement run failed (${result}):\n${output}\n${error}")
endif()

set(pids)
foreach(role client server)
  string(REGEX MATCHALL "probe setup ${role} pid=[0-9]+" setups "${output}")
  list(LENGTH setups setup_count)
  if(NOT setup_count EQUAL 2)
    message(FATAL_ERROR "Expected two fresh ${role} setups:\n${output}")
  endif()
  foreach(setup IN LISTS setups)
    string(REGEX REPLACE ".*pid=" "" pid "${setup}")
    list(APPEND pids "${pid}")
  endforeach()

  foreach(event exchange teardown)
    string(REGEX MATCHALL "probe ${event} ${role}" events "${output}")
    list(LENGTH events event_count)
    if(NOT event_count EQUAL 2)
      message(FATAL_ERROR "Expected two ${role} ${event} events:\n${output}")
    endif()
  endforeach()
endforeach()

list(REMOVE_DUPLICATES pids)
list(LENGTH pids process_count)
if(NOT process_count EQUAL 4)
  message(FATAL_ERROR "Measurements reused role processes:\n${output}")
endif()

if(NOT output MATCHES "all roles finished")
  message(FATAL_ERROR "Director did not finish successfully:\n${output}")
endif()
