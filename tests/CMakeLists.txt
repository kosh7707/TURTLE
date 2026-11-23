cmake_minimum_required(VERSION 3.20)
project(turtle_tests LANGUAGES C CXX)
enable_testing()
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/.." "${CMAKE_CURRENT_BINARY_DIR}/framework")
set(TURTLE_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/framework" CACHE PATH "Endpoint and CLI build directory")
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
add_executable(analysis analysis.cpp)
target_link_libraries(analysis PRIVATE turtle_analysis turtle_capture turtle_profiling)
add_test(NAME deterministic_analysis COMMAND analysis "${CMAKE_CURRENT_LIST_DIR}/fixtures" "${CMAKE_CURRENT_BINARY_DIR}/artifacts/deterministic")
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
