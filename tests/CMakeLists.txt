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
option(TURTLE_TEST_OPENSSL "Run real OpenSSL integration" OFF)
option(TURTLE_TEST_WOLFSSL "Run wolfSSL and cross-library integration" OFF)
option(TURTLE_TEST_NETEM "Run actual namespaces and libpcap (requires privileges)" OFF)
option(TURTLE_TEST_PERF "Run actual counters and stock perf" OFF)
set(TURTLE_PERF_EXECUTABLE "" CACHE FILEPATH "Stock perf record/script executable")
set(TURTLE_OPENSSL_ALTERNATE "" CACHE FILEPATH "Same adapter built against another OpenSSL")
add_executable(framing framing.cpp)
target_include_directories(framing PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../src")
target_link_libraries(framing PRIVATE turtle::core)
add_test(NAME incremental_framing COMMAND framing)
add_executable(c_contract contract.c)
target_link_libraries(c_contract PRIVATE turtle::endpoint)
add_test(NAME c_contract_link COMMAND c_contract)
add_library(turtle-role-contract OBJECT role_engine_contract.c)
target_link_libraries(turtle-role-contract PRIVATE turtle::contract)
add_executable(turtle-role-engine-test role_engine.cpp)
target_link_libraries(turtle-role-engine-test PRIVATE turtle::endpoint)
add_test(NAME role_engine COMMAND turtle-role-engine-test)
add_test(NAME installed_role_engine COMMAND "${CMAKE_COMMAND}"
    "-DSOURCE=${CMAKE_CURRENT_SOURCE_DIR}/role_engine.cpp" "-DBUILD=${CMAKE_BINARY_DIR}"
    "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/installed-role" -P "${CMAKE_CURRENT_SOURCE_DIR}/role_engine_install.cmake")
add_executable(analysis analysis.cpp)
target_link_libraries(analysis PRIVATE turtle_analysis turtle_capture turtle_profiling)
add_test(NAME deterministic_analysis COMMAND analysis "${CMAKE_CURRENT_LIST_DIR}/fixtures" "${CMAKE_CURRENT_BINARY_DIR}/artifacts/deterministic")
add_executable(turtle-pmu-evidence pmu_evidence.cpp)
target_include_directories(turtle-pmu-evidence PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../src")
target_link_libraries(turtle-pmu-evidence PRIVATE turtle_core turtle_analysis)
foreach(mode live denied offline)
    add_test(NAME pmu_${mode} COMMAND turtle-pmu-evidence ${mode} "${CMAKE_CURRENT_BINARY_DIR}/artifacts/pmu-${mode}")
endforeach()
set_tests_properties(pmu_live pmu_denied PROPERTIES SKIP_RETURN_CODE 77)
add_executable(spec_resolution spec.cpp)
target_link_libraries(spec_resolution PRIVATE turtle_control)
add_test(NAME spec_resolution COMMAND spec_resolution)
add_executable(tls_integration integration.cpp)
target_link_libraries(tls_integration PRIVATE turtle_process)
foreach(target framing analysis spec_resolution tls_integration)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
endforeach()
if(TURTLE_TEST_OPENSSL)
    find_program(OPENSSL_CLI openssl HINTS "${OPENSSL_ROOT_DIR}/bin" REQUIRED)
    set(implementations openssl)
    if(TURTLE_TEST_WOLFSSL)
        list(APPEND implementations wolfssl)
    endif()
    add_executable(partial_request partial-request.cpp)
    target_link_libraries(partial_request PRIVATE turtle_process)
    foreach(i IN LISTS implementations)
        if(TARGET turtle-${i})
            set(endpoint_${i} "$<TARGET_FILE:turtle-${i}>")
        else()
            set(endpoint_${i} "${TURTLE_BINARY_DIR}/turtle-${i}")
        endif()
        add_test(NAME partial_request_${i} COMMAND partial_request "${OPENSSL_CLI}" "${endpoint_${i}}"
            "${CMAKE_CURRENT_BINARY_DIR}/artifacts/partial_request_${i}")
    endforeach()
    add_test(NAME lifecycle_gates COMMAND tls_integration gates
        "${TURTLE_BINARY_DIR}/turtle" "${OPENSSL_CLI}" "${endpoint_openssl}" "${endpoint_openssl}" classical
        "${CMAKE_CURRENT_BINARY_DIR}/artifacts/lifecycle_gates")
    add_test(NAME retry_lineage COMMAND tls_integration retry
        "${TURTLE_BINARY_DIR}/turtle" "${OPENSSL_CLI}" "${endpoint_openssl}" "${endpoint_openssl}" classical
        "${CMAKE_CURRENT_BINARY_DIR}/artifacts/retry_lineage")
    add_test(NAME recording_cost COMMAND tls_integration overhead
        "${TURTLE_BINARY_DIR}/turtle" "${OPENSSL_CLI}" "${endpoint_openssl}" "${endpoint_openssl}" classical
        "${CMAKE_CURRENT_BINARY_DIR}/artifacts/recording_cost")
    foreach(client IN LISTS implementations)
        foreach(server IN LISTS implementations)
            foreach(profile classical hybrid mldsa chain partial)
                set(name "tls_${client}_${server}_${profile}")
                add_test(NAME "${name}" COMMAND tls_integration loopback
                    "${TURTLE_BINARY_DIR}/turtle" "${OPENSSL_CLI}"
                    "${endpoint_${client}}" "${endpoint_${server}}"
                    "${profile}" "${CMAKE_CURRENT_BINARY_DIR}/artifacts/${name}")
                set_tests_properties("${name}" PROPERTIES TIMEOUT 180)
            endforeach()
        endforeach()
    endforeach()
    if(TURTLE_OPENSSL_ALTERNATE)
        foreach(profile classical chain)
            add_test(NAME "tls_alternate_${profile}" COMMAND tls_integration loopback
                "${TURTLE_BINARY_DIR}/turtle" "${OPENSSL_CLI}"
                "${TURTLE_OPENSSL_ALTERNATE}" "${TURTLE_OPENSSL_ALTERNATE}"
                "${profile}" "${CMAKE_CURRENT_BINARY_DIR}/artifacts/alternate_${profile}")
        endforeach()
    endif()
    if(TURTLE_TEST_NETEM)
        add_test(NAME actual_netem COMMAND tls_integration netem "${TURTLE_BINARY_DIR}/turtle" "${OPENSSL_CLI}"
            "${endpoint_openssl}" "${endpoint_openssl}" chain
            "${CMAKE_CURRENT_BINARY_DIR}/artifacts/netem")
        set_tests_properties(actual_netem PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
        add_test(NAME interrupted_netem COMMAND tls_integration interrupt "${TURTLE_BINARY_DIR}/turtle" "${OPENSSL_CLI}"
            "${endpoint_openssl}" "${endpoint_openssl}" classical
            "${CMAKE_CURRENT_BINARY_DIR}/artifacts/interrupted")
        set_tests_properties(interrupted_netem PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE)
    endif()
    if(TURTLE_TEST_PERF)
        if(NOT TURTLE_PERF_EXECUTABLE)
            find_program(TURTLE_PERF_EXECUTABLE perf REQUIRED)
        endif()
        foreach(implementation IN LISTS implementations)
            foreach(mode counter sample cycles)
                add_test(NAME "perf_${implementation}_${mode}" COMMAND tls_integration "${mode}"
                    "${TURTLE_BINARY_DIR}/turtle" "${OPENSSL_CLI}"
                    "${endpoint_${implementation}}" "${endpoint_${implementation}}" chain
                    "${CMAKE_CURRENT_BINARY_DIR}/artifacts/perf_${implementation}_${mode}" "${TURTLE_PERF_EXECUTABLE}")
                set_tests_properties("perf_${implementation}_${mode}" PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE)
            endforeach()
        endforeach()
    endif()
endif()
add_test(NAME implementation_registration COMMAND "${CMAKE_COMMAND}"
    "-DTURTLE_SOURCE=${CMAKE_CURRENT_LIST_DIR}/.." "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/artifacts/registration"
    "-DDEPENDENCY_PREFIX=${CMAKE_PREFIX_PATH}" -P "${CMAKE_CURRENT_LIST_DIR}/registration.cmake")
set_tests_properties(implementation_registration PROPERTIES TIMEOUT 240)
add_test(NAME component_boundaries COMMAND "${CMAKE_COMMAND}" "-DROOT=${CMAKE_CURRENT_LIST_DIR}/.." -P "${CMAKE_CURRENT_LIST_DIR}/boundaries.cmake")

if(TARGET turtle-reference AND TARGET turtle-openssl)
    find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
    add_executable(turtle-one-side-fault one_side_fault.cpp)
    target_link_libraries(turtle-one-side-fault PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    add_executable(turtle-one-side-test one_side.cpp)
    target_link_libraries(turtle-one-side-test PRIVATE turtle_process)
    add_test(NAME one_sided_mtls_s3 COMMAND turtle-one-side-test "$<TARGET_FILE:turtle>"
        "$<TARGET_FILE:turtle-openssl>" "${CMAKE_CURRENT_BINARY_DIR}/artifacts/one-sided"
        "$<TARGET_FILE:turtle-one-side-fault>")
    set_tests_properties(one_sided_mtls_s3 PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)
endif()

add_test(NAME pair_diagnostics COMMAND sh "${CMAKE_CURRENT_LIST_DIR}/pair.sh" "$<TARGET_FILE:turtle-pair>")
set_tests_properties(pair_diagnostics PROPERTIES TIMEOUT 60)
