find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(TURTLE_OPENSSL_PROGRAM openssl REQUIRED)
set(test_pki "${CMAKE_BINARY_DIR}/pki")
add_test(NAME local_test_certificates
  COMMAND ${CMAKE_COMMAND} -E env "OPENSSL=${TURTLE_OPENSSL_PROGRAM}"
    bash "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/make-pki.sh" "${test_pki}")
set_tests_properties(local_test_certificates PROPERTIES FIXTURES_SETUP local_pki TIMEOUT 30)
add_test(NAME local_pki_matrix COMMAND ${Python3_EXECUTABLE}
  "${CMAKE_CURRENT_SOURCE_DIR}/pki.py"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/make-pki.sh" "${TURTLE_OPENSSL_PROGRAM}")
set_tests_properties(local_pki_matrix PROPERTIES TIMEOUT 60 LABELS integration)

# Contract-only coordinator coverage with a fake director.  The privileged
# fixed N05 loss gate is an explicit one-shot verification and is never a
# repeated CTest.
add_test(NAME netem_runner_contracts COMMAND ${Python3_EXECUTABLE}
  "${CMAKE_CURRENT_SOURCE_DIR}/netem.py"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/netem-study.py")
set_tests_properties(netem_runner_contracts PROPERTIES TIMEOUT 30 LABELS integration)

set(adapters)
foreach(name openssl wolfssl mbedtls)
  if(TARGET turtle_adapter_${name})
    list(APPEND adapters ${name})
  endif()
endforeach()
if(TARGET turtle_adapter_openssl AND TARGET turtle-report AND TARGET turtle-interpret)
  add_test(NAME pure_tls_netem_actual COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/pure_tls_netem.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/netem-study.py"
    "$<TARGET_FILE:turtle>" "$<TARGET_FILE:turtle-report>"
    "$<TARGET_FILE:turtle-interpret>" "${CMAKE_BINARY_DIR}/adapters" "${test_pki}")
  set_tests_properties(pure_tls_netem_actual PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 240 LABELS integration)
  add_test(NAME pipeline_multiple_connections COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/pipeline.py"
    "$<TARGET_FILE:turtle>" "$<TARGET_FILE:turtle-report>" "$<TARGET_FILE:turtle-interpret>"
    "${CMAKE_BINARY_DIR}/adapters" "${test_pki}" openssl openssl 2)
  set_tests_properties(pipeline_multiple_connections PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 60 LABELS integration)
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
  if(TARGET turtle-report AND TARGET turtle-interpret)
    add_test(NAME lookup_${name}_same_library COMMAND ${Python3_EXECUTABLE}
      "${CMAKE_CURRENT_SOURCE_DIR}/lookup.py"
      "$<TARGET_FILE:turtle>" "$<TARGET_FILE:turtle-report>" "$<TARGET_FILE:turtle-interpret>"
      "${CMAKE_BINARY_DIR}/adapters" "${test_pki}" "${name}")
    set_tests_properties(lookup_${name}_same_library PROPERTIES
      FIXTURES_REQUIRED local_pki TIMEOUT 240 LABELS integration)
  endif()
endforeach()
