cmake_minimum_required(VERSION 3.20)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(turtle_tests LANGUAGES C CXX)
    enable_testing()
    set(framework_binary "${CMAKE_CURRENT_BINARY_DIR}/framework")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/.." "${framework_binary}")
else()
    set(framework_binary "${PROJECT_BINARY_DIR}")
endif()
set(TURTLE_BINARY_DIR "${framework_binary}" CACHE PATH "Endpoint and CLI build directory")
add_test(NAME source_language_policy COMMAND sh "${CMAKE_CURRENT_LIST_DIR}/language-policy.sh"
    "${CMAKE_CURRENT_LIST_DIR}/..")
add_test(NAME source_language_policy_regression COMMAND sh "${CMAKE_CURRENT_LIST_DIR}/language-policy-test.sh")
# Historical raw records and deterministic framing/PMU checks remain readable
# independently of the optional TLS peer. These helpers are not an installed SDK.
add_library(turtle_test_recording STATIC ../src/frame/framer.cpp ../src/measure/recorder.cpp ../src/measure/perf.cpp
    ../src/artifact/endpoint.cpp)
target_include_directories(turtle_test_recording PUBLIC "${CMAKE_CURRENT_LIST_DIR}/../src")
target_link_libraries(turtle_test_recording PUBLIC turtle_artifact)
if(TURTLE_WITH_PMU STREQUAL "OFF" OR NOT TURTLE_PMU_INTERFACE)
    target_compile_definitions(turtle_test_recording PRIVATE TURTLE_NO_PMU)
endif()
add_executable(framing framing.cpp)
target_include_directories(framing PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../src")
target_link_libraries(framing PRIVATE turtle_test_recording)
add_test(NAME incremental_framing COMMAND framing)
add_executable(analysis analysis.cpp)
target_link_libraries(analysis PRIVATE turtle_analysis turtle_capture turtle_profiling)
add_test(NAME deterministic_analysis COMMAND analysis "${CMAKE_CURRENT_LIST_DIR}/fixtures" "${CMAKE_CURRENT_BINARY_DIR}/artifacts/deterministic")
add_executable(turtle-pmu-evidence pmu_evidence.cpp)
target_include_directories(turtle-pmu-evidence PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../src")
target_link_libraries(turtle-pmu-evidence PRIVATE turtle_test_recording turtle_analysis)
foreach(mode live denied offline)
    add_test(NAME pmu_${mode} COMMAND turtle-pmu-evidence ${mode} "${CMAKE_CURRENT_BINARY_DIR}/artifacts/pmu-${mode}")
endforeach()
set_tests_properties(pmu_live pmu_denied PROPERTIES SKIP_RETURN_CODE 77)
add_executable(spec_resolution spec.cpp)
# Archived configuration policy is tested, not a live execution route.
add_library(turtle_test_config STATIC ../src/control/spec.cpp)
target_link_libraries(turtle_test_config PUBLIC turtle_process turtle_capture turtle_profiling)
target_link_libraries(spec_resolution PRIVATE turtle_test_config)
add_test(NAME spec_resolution COMMAND spec_resolution)
add_test(NAME component_boundaries COMMAND "${CMAKE_COMMAND}" "-DROOT=${CMAKE_CURRENT_LIST_DIR}/.." -P "${CMAKE_CURRENT_LIST_DIR}/boundaries.cmake")

add_test(NAME pair_diagnostics COMMAND sh "${CMAKE_CURRENT_LIST_DIR}/pair.sh" "$<TARGET_FILE:turtle-pair>")
set_tests_properties(pair_diagnostics PROPERTIES TIMEOUT 60)

add_executable(turtle-scenario-vectors scenario_vectors.cpp)
target_link_libraries(turtle-scenario-vectors PRIVATE turtle_analysis)
add_test(NAME scenario_s4_plaintext_vectors COMMAND turtle-scenario-vectors
    "${CMAKE_CURRENT_BINARY_DIR}/artifacts/scenario-vectors")

add_executable(turtle-network-evidence network_evidence.cpp)
target_link_libraries(turtle-network-evidence PRIVATE turtle_test_config)
add_test(NAME netem_evidence COMMAND turtle-network-evidence)


add_executable(turtle-atomic-artifact atomic_artifact.cpp)
target_link_libraries(turtle-atomic-artifact PRIVATE turtle_analysis)
add_test(NAME atomic_artifact COMMAND turtle-atomic-artifact
    "${CMAKE_CURRENT_BINARY_DIR}/artifacts/atomic-writes")

add_executable(turtle-profile-catalog profile_catalog.cpp)
target_link_libraries(turtle-profile-catalog PRIVATE turtle_profiling)
add_test(NAME profile_catalog COMMAND turtle-profile-catalog
    "${CMAKE_CURRENT_BINARY_DIR}/artifacts/profile-catalog" "${CMAKE_CURRENT_LIST_DIR}/profile-catalog-tool.sh")

add_library(turtle-image-module MODULE image_module.c)
add_executable(turtle-image-binding-test image_binding.cpp)
target_link_libraries(turtle-image-binding-test PRIVATE turtle_process ${CMAKE_DL_LIBS})
add_test(NAME participant_image_inventory COMMAND turtle-image-binding-test "$<TARGET_FILE:turtle-image-module>")
if(TARGET turtle-reference)
    find_program(OPENSSL_CLI openssl REQUIRED)
    add_test(NAME native_cli_contract COMMAND sh "${CMAKE_CURRENT_LIST_DIR}/native-cli-regression.sh"
        "$<TARGET_FILE:turtle>" "${OPENSSL_CLI}")
    set_tests_properties(native_cli_contract PROPERTIES TIMEOUT 60)
    add_test(NAME endpoint_installed_tls_matrix COMMAND sh "${CMAKE_CURRENT_LIST_DIR}/endpoint-integration.sh"
        "${framework_binary}" "${CMAKE_CURRENT_BINARY_DIR}/endpoint-matrix")
    set_tests_properties(endpoint_installed_tls_matrix PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE)
    add_executable(partial_request partial-request.cpp)
    target_link_libraries(partial_request PRIVATE turtle_process)
    add_test(NAME reference_rejects_invalid_request COMMAND partial_request "${OPENSSL_CLI}"
        "$<TARGET_FILE:turtle-reference>" "${CMAKE_CURRENT_BINARY_DIR}/artifacts/partial-request")
    set_tests_properties(reference_rejects_invalid_request PROPERTIES TIMEOUT 90)
endif()
add_test(NAME installed_c_observer COMMAND "${CMAKE_COMMAND}"
    "-DBUILD=${framework_binary}" "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/installed-c-observer"
    -P "${CMAKE_CURRENT_LIST_DIR}/observer-install.cmake")
add_executable(turtle-native-evidence-test native_evidence.cpp)
target_link_libraries(turtle-native-evidence-test PRIVATE turtle_native_evidence turtle_observe)
add_test(NAME native_evidence COMMAND turtle-native-evidence-test)

add_executable(turtle-observer-fd observer-fd.cpp)
target_link_libraries(turtle-observer-fd PRIVATE turtle_observe)
add_test(NAME observer_fd_contract COMMAND turtle-observer-fd)
if(TARGET turtle_pcap)
    add_executable(turtle-native-packets native-packets.cpp)
    target_link_libraries(turtle-native-packets PRIVATE turtle_native turtle_capture)
    add_test(NAME native_packet_replay COMMAND turtle-native-packets)
endif()

# Explicit release tests: never silently skip an absent independent application,
# hardware counter or networking prerequisite.
option(TURTLE_TEST_NATIVE_MATRIX "Run the external GnuTLS admission matrix" OFF)
if(TURTLE_TEST_NATIVE_MATRIX)
    find_program(TURTLE_GNUTLS_CLI gnutls-cli REQUIRED)
    add_test(NAME native_release_matrix COMMAND sh -c
        [=["$1" "$2" "$3" "$(mktemp -d)/matrix"]=] sh
        "${CMAKE_CURRENT_LIST_DIR}/native-matrix.sh" "${framework_binary}" "${TURTLE_GNUTLS_CLI}")
    set_tests_properties(native_release_matrix PROPERTIES RUN_SERIAL TRUE TIMEOUT 1200)
endif()
option(TURTLE_TEST_NETEM "Verify native collection and replay in isolated namespaces" OFF)
if(TURTLE_TEST_NETEM)
    set(TURTLE_NATIVE_TEST_APP "" CACHE FILEPATH "Independently built observed line app (native-matrix.sh output chat)")
    if(NOT TARGET turtle-reference OR NOT TARGET turtle_pcap OR NOT EXISTS "${TURTLE_NATIVE_TEST_APP}")
        message(FATAL_ERROR "Native netem test needs reference, libpcap, and TURTLE_NATIVE_TEST_APP")
    endif()
    add_test(NAME native_netem_capture COMMAND sh "${CMAKE_CURRENT_LIST_DIR}/native-network.sh"
        "$<TARGET_FILE:turtle>" "${TURTLE_NATIVE_TEST_APP}" "${CMAKE_CURRENT_BINARY_DIR}/artifacts")
    set_tests_properties(native_netem_capture PROPERTIES RUN_SERIAL TRUE TIMEOUT 300)
endif()

add_executable(turtle-native-prepared native-prepared.cpp)
target_link_libraries(turtle-native-prepared PRIVATE turtle_artifact)
add_test(NAME native_prepared_start COMMAND turtle-native-prepared)

add_executable(turtle-native-probe-test native-probe.cpp)
target_link_libraries(turtle-native-probe-test PRIVATE turtle_native)
add_test(NAME native_prefinished_queue_bound COMMAND turtle-native-probe-test)

add_executable(turtle-endpoint-runner-test endpoint-runner.c)
target_link_libraries(turtle-endpoint-runner-test PRIVATE turtle::endpoint)
add_executable(turtle-endpoint-runner-replay endpoint-runner-replay.cpp)
target_link_libraries(turtle-endpoint-runner-replay PRIVATE turtle_native_evidence)
add_test(NAME endpoint_runner COMMAND sh "${CMAKE_CURRENT_LIST_DIR}/endpoint-runner.sh"
    "$<TARGET_FILE:turtle-endpoint-runner-test>" "$<TARGET_FILE:turtle-endpoint-runner-replay>")
