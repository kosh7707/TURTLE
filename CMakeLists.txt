cmake_minimum_required(VERSION 3.20)
project(turtle VERSION 1.0.0 LANGUAGES C CXX)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "TURTLE requires Linux")
endif()
find_package(nlohmann_json 3.12 QUIET CONFIG HINTS
    "${CMAKE_CURRENT_SOURCE_DIR}/.deps/prepared/json-3.12.0/install")
if(NOT nlohmann_json_FOUND)
    message(FATAL_ERROR "Install nlohmann_json 3.12 or run: cmake -DNAME=json -DVERSION=3.12.0 -P tools/dependencies.cmake")
endif()
foreach(feature PCAP PMU)
    set(TURTLE_WITH_${feature} AUTO CACHE STRING "Enable ${feature}: AUTO, ON, or OFF")
    set_property(CACHE TURTLE_WITH_${feature} PROPERTY STRINGS AUTO ON OFF)
    if(NOT TURTLE_WITH_${feature} MATCHES "^(AUTO|ON|OFF)$")
        message(FATAL_ERROR "TURTLE_WITH_${feature} must be AUTO, ON or OFF")
    endif()
endforeach()
if(NOT TURTLE_WITH_PCAP STREQUAL "OFF")
    find_path(TURTLE_PCAP_INCLUDE_DIR pcap/pcap.h)
    find_library(TURTLE_PCAP_LIBRARY pcap)
    if(TURTLE_PCAP_INCLUDE_DIR AND TURTLE_PCAP_LIBRARY)
        add_library(turtle_pcap UNKNOWN IMPORTED)
        set_target_properties(turtle_pcap PROPERTIES IMPORTED_LOCATION "${TURTLE_PCAP_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${TURTLE_PCAP_INCLUDE_DIR}")
    elseif(TURTLE_WITH_PCAP STREQUAL "ON")
        message(FATAL_ERROR "Requested libpcap development files not found")
    endif()
endif()
if(NOT TURTLE_WITH_PMU STREQUAL "OFF")
    include(CheckCXXSourceCompiles)
    check_cxx_source_compiles("#include <linux/perf_event.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(){perf_event_attr a{}; return syscall(SYS_perf_event_open,&a,0,-1,-1,0);}" TURTLE_PMU_INTERFACE)
    if(NOT TURTLE_PMU_INTERFACE AND TURTLE_WITH_PMU STREQUAL "ON")
        message(FATAL_ERROR "Requested Linux PMU interface not available")
    endif()
endif()
add_library(turtle_artifact STATIC src/artifact/json.cpp)
target_link_libraries(turtle_artifact PUBLIC "$<BUILD_INTERFACE:nlohmann_json::nlohmann_json>")
target_include_directories(turtle_artifact PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>")
target_compile_features(turtle_artifact PUBLIC cxx_std_20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

add_library(turtle_contract INTERFACE)
add_library(turtle::contract ALIAS turtle_contract)
target_include_directories(turtle_contract INTERFACE "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>" "$<INSTALL_INTERFACE:include>")

add_library(turtle_core STATIC
    src/frame/framer.cpp
    src/measure/recorder.cpp
    src/measure/perf.cpp
    src/net/transport.cpp
    src/artifact/endpoint.cpp)
if(TURTLE_WITH_PMU STREQUAL "OFF" OR NOT TURTLE_PMU_INTERFACE)
    target_compile_definitions(turtle_core PRIVATE TURTLE_NO_PMU)
endif()
add_library(turtle::core ALIAS turtle_core)
target_include_directories(turtle_core PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(turtle_core PUBLIC turtle_contract PRIVATE turtle_artifact)
target_compile_features(turtle_core PUBLIC cxx_std_20)
target_compile_options(turtle_core PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(turtle_core PROPERTIES CXX_EXTENSIONS OFF)

add_library(turtle_endpoint STATIC src/endpoint/endpoint.cpp src/run/role.cpp src/run/runner.cpp)
add_library(turtle::endpoint ALIAS turtle_endpoint)
target_include_directories(turtle_endpoint PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(turtle_endpoint PUBLIC turtle::core PRIVATE turtle_artifact)
target_compile_options(turtle_endpoint PRIVATE -Wall -Wextra -Wpedantic)

set(TURTLE_IMPLEMENTATION_DIRS "" CACHE STRING
    "Semicolon-separated directories containing user-supplied CMakeLists.txt files")
option(TURTLE_BUILD_REFERENCE "Build the default peer for one-sided benchmarks" ON)
set(TURTLE_REFERENCE_RUNTIME_DIR "${CMAKE_CURRENT_BINARY_DIR}")
foreach(directory IN LISTS TURTLE_IMPLEMENTATION_DIRS)
    get_filename_component(source "${directory}" REALPATH BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    if(NOT EXISTS "${source}/CMakeLists.txt")
        message(FATAL_ERROR "Implementation build definition not found: ${source}/CMakeLists.txt")
    endif()
    string(SHA256 key "${source}")
    string(SUBSTRING "${key}" 0 16 key)
    add_subdirectory("${source}" "${CMAKE_CURRENT_BINARY_DIR}/implementations/${key}")
endforeach()

if(TURTLE_BUILD_REFERENCE AND NOT TARGET turtle-reference)
    add_subdirectory(implementations/openssl reference)
endif()

add_library(turtle_process STATIC src/process/process.cpp)
target_link_libraries(turtle_process PUBLIC turtle_artifact)
add_library(turtle_capture STATIC src/capture/capture.cpp)
target_link_libraries(turtle_capture PUBLIC turtle_artifact)
if(TARGET turtle_pcap)
    target_link_libraries(turtle_capture PRIVATE turtle_pcap)
else()
    target_compile_definitions(turtle_capture PUBLIC TURTLE_NO_PCAP)
endif()
add_library(turtle_profiling STATIC src/profiling/profiling.cpp)
target_link_libraries(turtle_profiling PUBLIC turtle_process)
add_library(turtle_analysis STATIC
    src/analysis/endpoint.cpp
    src/analysis/phases.cpp
    src/analysis/counters.cpp
    src/analysis/attempt.cpp
    src/analysis/lifecycle.cpp
    src/analysis/observations.cpp
    src/analysis/record_semantics.cpp
    src/analysis/tcp_evidence.cpp)
target_link_libraries(turtle_analysis PUBLIC turtle_artifact PRIVATE turtle_capture turtle_profiling turtle_process)
add_library(turtle_control STATIC src/control/network.cpp src/control/spec.cpp src/control/controller.cpp src/control/retry.cpp src/control/one_side.cpp)
target_link_libraries(turtle_control PUBLIC turtle_process PRIVATE turtle_analysis turtle_profiling turtle_capture)
file(GLOB_RECURSE turtle_sources CONFIGURE_DEPENDS src/*.cpp src/*.hpp include/*.h cmake/*)
list(APPEND turtle_sources "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${turtle_sources})
set(turtle_source_fingerprints "")
foreach(source IN LISTS turtle_sources)
    file(SHA256 "${source}" hash)
    file(RELATIVE_PATH name "${CMAKE_CURRENT_SOURCE_DIR}" "${source}")
    string(APPEND turtle_source_fingerprints "${name}:${hash}\n")
endforeach()
string(SHA256 turtle_source_sha256 "${turtle_source_fingerprints}")
configure_file(cmake/build_info.hpp.in generated/build_info.hpp @ONLY)
target_include_directories(turtle_control PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
add_executable(turtle src/cli/main.cpp)
if(TARGET turtle-reference)
    add_dependencies(turtle turtle-reference)
endif()
target_link_libraries(turtle PRIVATE turtle_control turtle_analysis turtle_capture)
foreach(target turtle_artifact turtle_process turtle_capture turtle_profiling turtle_analysis turtle_control turtle)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF)
endforeach()
include(GNUInstallDirs)
find_package(Threads REQUIRED)
add_executable(turtle-pair src/pair/main.cpp src/pair/mock.cpp)
target_compile_options(turtle-pair PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(turtle-pair PRIVATE turtle_process turtle::contract Threads::Threads)
install(TARGETS turtle-pair RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
configure_file(examples/issue-test-leaves.sh turtle-issue-test-leaves.sh COPYONLY)
install(PROGRAMS examples/issue-test-leaves.sh DESTINATION ${CMAKE_INSTALL_BINDIR}
    RENAME turtle-issue-test-leaves.sh)
if(TARGET turtle-reference)
    install(TARGETS turtle-reference RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(TARGETS turtle RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/turtle DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PATTERN "io_boundary.h" EXCLUDE)
install(FILES implementations/implementation.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/turtle
    RENAME io_boundary.h)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/generated/build_info.hpp" DESTINATION ${CMAKE_INSTALL_DATADIR}/turtle)
# An adapter can build against an installed SDK without the controller, JSON headers
# or any other adapter in its source tree.
foreach(component contract core endpoint artifact)
    set_target_properties(turtle_${component} PROPERTIES EXPORT_NAME ${component})
endforeach()
install(TARGETS turtle_contract turtle_endpoint turtle_core turtle_artifact EXPORT turtleTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(EXPORT turtleTargets FILE TURTLEConfig.cmake NAMESPACE turtle::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TURTLE)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    include(CTest)
    if(BUILD_TESTING)
        add_subdirectory(tests)
    endif()
endif()
