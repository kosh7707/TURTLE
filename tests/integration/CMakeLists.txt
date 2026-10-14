find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(TURTLE_OPENSSL_PROGRAM openssl REQUIRED)
set(test_pki "${CMAKE_BINARY_DIR}/pki")
add_test(NAME local_test_certificates
  COMMAND ${CMAKE_COMMAND} -E env "OPENSSL=${TURTLE_OPENSSL_PROGRAM}"
    bash "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/make-pki.sh" "${test_pki}")
set_tests_properties(local_test_certificates PROPERTIES FIXTURES_SETUP local_pki TIMEOUT 30)

set(adapters)
foreach(name openssl wolfssl mbedtls)
  if(TARGET turtle_adapter_${name})
    list(APPEND adapters ${name})
  endif()
endforeach()
if(TARGET turtle_adapter_openssl AND TARGET turtle-interpret)
  add_test(NAME openssl_tickets_and_message_oracle COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/tickets.py"
    "$<TARGET_FILE:turtle>" "$<TARGET_FILE:turtle-report>" "$<TARGET_FILE:turtle-interpret>"
    "${CMAKE_BINARY_DIR}/adapters" "${test_pki}")
  set_tests_properties(openssl_tickets_and_message_oracle PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 30 LABELS integration)
endif()
foreach(client IN LISTS adapters)
  foreach(server IN LISTS adapters)
    foreach(auth server mutual)
      set(test_name adapter_${client}_${server}_${auth})
      add_test(NAME ${test_name} COMMAND turtle_adapter_smoke
        "$<TARGET_FILE:turtle_adapter_${client}>" "$<TARGET_FILE:turtle_adapter_${server}>"
        "${test_pki}" "${auth}")
      set_tests_properties(${test_name} PROPERTIES FIXTURES_REQUIRED local_pki TIMEOUT 15)
    endforeach()
    if(TARGET turtle-interpret)
      set(test_name pipeline_${client}_${server})
      add_test(NAME ${test_name} COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/pipeline.py"
        "$<TARGET_FILE:turtle>" "$<TARGET_FILE:turtle-report>" "$<TARGET_FILE:turtle-interpret>"
        "${CMAKE_BINARY_DIR}/adapters" "${test_pki}" "${client}" "${server}")
      set_tests_properties(${test_name} PROPERTIES FIXTURES_REQUIRED local_pki TIMEOUT 60 LABELS integration)
    endif()
  endforeach()
endforeach()
foreach(name IN LISTS adapters)
  add_test(NAME ${name}_allocator_lifetime COMMAND turtle_adapter_memory
    "$<TARGET_FILE:turtle_adapter_${name}>" "${test_pki}")
  set_tests_properties(${name}_allocator_lifetime PROPERTIES FIXTURES_REQUIRED local_pki TIMEOUT 15)
endforeach()
