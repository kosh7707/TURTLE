find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(TURTLE_OPENSSL_PROGRAM openssl REQUIRED)
add_test(NAME kernel_event_byte_ranges COMMAND ${Python3_EXECUTABLE} -B
  "${CMAKE_CURRENT_SOURCE_DIR}/kernel_events.py"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/kernel_observer.py")
add_test(NAME cpu_sample_analysis COMMAND ${Python3_EXECUTABLE} -B
  "${CMAKE_CURRENT_SOURCE_DIR}/cpu_profile.py"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/cpu-profile.py" "$<TARGET_FILE:turtle>")
add_test(NAME tcp_byte_correlation COMMAND ${Python3_EXECUTABLE} -B
  "${CMAKE_CURRENT_SOURCE_DIR}/tcp_correlate.py"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/tcp-correlate.py")
add_test(NAME study_runner_contracts COMMAND ${Python3_EXECUTABLE} -B
  "${CMAKE_CURRENT_SOURCE_DIR}/study.py"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/run-study.py")
set_tests_properties(study_runner_contracts PROPERTIES TIMEOUT 30)
add_test(NAME repeated_context_report_contracts COMMAND ${Python3_EXECUTABLE} -B
  "${CMAKE_CURRENT_SOURCE_DIR}/repeated_context.py"
  "$<TARGET_FILE:turtle-report>")
set_tests_properties(repeated_context_report_contracts PROPERTIES TIMEOUT 60)
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
set(openssl_cli_evidence_root "${CMAKE_BINARY_DIR}/test-results/openssl-cli")
foreach(adapter IN LISTS adapters)
  foreach(role client server)
    foreach(auth server mutual)
      set(test_name openssl_cli_${adapter}_${role}_${auth})
      add_test(NAME ${test_name} COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/openssl_cli.py"
        --endpoint "$<TARGET_FILE:turtle_adapter_cli_endpoint>"
        --openssl "${TURTLE_OPENSSL_PROGRAM}"
        --adapter "$<TARGET_FILE:turtle_adapter_${adapter}>"
        --pki "${test_pki}"
        --role "${role}"
        --auth "${auth}"
        --output "${openssl_cli_evidence_root}")
      set_tests_properties(${test_name} PROPERTIES
        FIXTURES_REQUIRED local_pki TIMEOUT 30 LABELS integration)
    endforeach()
  endforeach()
endforeach()
if(TARGET turtle_adapter_openssl AND TARGET turtle-report AND TARGET turtle-interpret)
  add_test(NAME observer_impact_normal COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/observer_impact.py"
    --turtle "$<TARGET_FILE:turtle>"
    --report "$<TARGET_FILE:turtle-report>"
    --interpret "$<TARGET_FILE:turtle-interpret>"
    --adapters "${CMAKE_BINARY_DIR}/adapters"
    --pki "${test_pki}"
    --output "${CMAKE_BINARY_DIR}/test-results/observer-impact")
  set_tests_properties(observer_impact_normal PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 180 LABELS integration)
  set(io_path_evidence_root "${CMAKE_BINARY_DIR}/test-results/io-path")
  add_test(NAME io_path_normal COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/io_path.py" normal
    --turtle "$<TARGET_FILE:turtle>"
    --report "$<TARGET_FILE:turtle-report>"
    --interpret "$<TARGET_FILE:turtle-interpret>"
    --adapters "${CMAKE_BINARY_DIR}/adapters"
    --pki "${test_pki}"
    --netem "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/netem-study.py"
    --output "${io_path_evidence_root}")
  set_tests_properties(io_path_normal PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 60 LABELS integration)
  add_test(NAME io_path_external_metadata COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/io_path.py" external
    --turtle "$<TARGET_FILE:turtle>"
    --report "$<TARGET_FILE:turtle-report>"
    --interpret "$<TARGET_FILE:turtle-interpret>"
    --adapters "${CMAKE_BINARY_DIR}/adapters"
    --pki "${test_pki}"
    --netem "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/netem-study.py"
    --output "${io_path_evidence_root}")
  set_tests_properties(io_path_external_metadata PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 180 LABELS integration SKIP_RETURN_CODE 77)
  add_test(NAME pure_tls_netem_actual COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/pure_tls_netem.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/netem-study.py"
    "$<TARGET_FILE:turtle>" "$<TARGET_FILE:turtle-report>"
    "$<TARGET_FILE:turtle-interpret>" "${CMAKE_BINARY_DIR}/adapters" "${test_pki}")
  set_tests_properties(pure_tls_netem_actual PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 240 LABELS integration)
  add_test(NAME network_rate_cwnd_actual_tls COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/network_shaping.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/netem-study.py"
    "$<TARGET_FILE:turtle>" "$<TARGET_FILE:turtle-report>"
    "$<TARGET_FILE:turtle-interpret>" "${CMAKE_BINARY_DIR}/adapters" "${test_pki}")
  set_tests_properties(network_rate_cwnd_actual_tls PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 90 LABELS integration)
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

if(TARGET turtle_adapter_openssl AND TARGET turtle-interpret)
  get_target_property(prototype_trace turtle_adapter_openssl TURTLE_INTERNAL_TRACE)
  if(prototype_trace)
  add_test(NAME kernel_tx_timestamps_actual_tls COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/tx_timestamps.py" "$<TARGET_FILE:turtle>"
    "$<TARGET_FILE:turtle-report>" "$<TARGET_FILE:turtle-interpret>"
    "${CMAKE_BINARY_DIR}/adapters" "${test_pki}")
  set_tests_properties(kernel_tx_timestamps_actual_tls PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 180 LABELS integration SKIP_RETURN_CODE 77)
  add_test(NAME prototype_scenarios_actual_tls COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/prototype.py" "$<TARGET_FILE:turtle>"
    "$<TARGET_FILE:turtle-report>" "$<TARGET_FILE:turtle-interpret>"
    "${CMAKE_BINARY_DIR}/adapters" "${test_pki}")
  set_tests_properties(prototype_scenarios_actual_tls PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 240 LABELS integration)
  endif()
endif()
if(TARGET turtle_adapter_bithac_cached AND TARGET turtle-interpret)
  add_test(NAME bithac_actual_cached_certificates COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/bithac.py" "$<TARGET_FILE:turtle>"
    "$<TARGET_FILE:turtle-report>" "$<TARGET_FILE:turtle-interpret>"
    "${CMAKE_BINARY_DIR}/adapters" "${test_pki}")
  set_tests_properties(bithac_actual_cached_certificates PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 180 LABELS integration)
endif()
if(TARGET turtle_adapter_mlkem_avx2 AND TARGET turtle-interpret)
  add_test(NAME mlkem_actual_dispatch_tls COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/mlkem.py" "$<TARGET_FILE:turtle>"
    "$<TARGET_FILE:turtle-report>" "$<TARGET_FILE:turtle-interpret>"
    "${CMAKE_BINARY_DIR}/adapters" "${test_pki}")
  set_tests_properties(mlkem_actual_dispatch_tls PROPERTIES
    FIXTURES_REQUIRED local_pki TIMEOUT 240 LABELS integration)
  foreach(variant c avx2)
    set(prefix "${TURTLE_DEPS_ROOT}/install/mlkem-${variant}")
    add_executable(turtle_mlkem_vectors_${variant} ../adapters/mlkem_vectors.cpp)
    target_include_directories(turtle_mlkem_vectors_${variant} SYSTEM PRIVATE "${prefix}/include")
    target_link_libraries(turtle_mlkem_vectors_${variant} PRIVATE "${prefix}/lib/libwolfssl.a" m pthread)
  endforeach()
  add_test(NAME mlkem_normal_vectors COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/mlkem_vectors.py"
    "$<TARGET_FILE:turtle_mlkem_vectors_c>" "$<TARGET_FILE:turtle_mlkem_vectors_avx2>"
    "${CMAKE_CURRENT_SOURCE_DIR}/../adapters/mlkem-vectors.json")
endif()
