cmake_minimum_required(VERSION 3.20)
project(turtle VERSION 1.0.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "TURTLE requires Linux")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(TURTLE_WITH_PMU AUTO CACHE STRING "Use Linux performance counters: AUTO, ON, or OFF")
set_property(CACHE TURTLE_WITH_PMU PROPERTY STRINGS AUTO ON OFF)
if(NOT TURTLE_WITH_PMU MATCHES "^(AUTO|ON|OFF)$")
    message(FATAL_ERROR "TURTLE_WITH_PMU must be AUTO, ON or OFF")
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

add_library(turtle-submission-cycles OBJECT src/measure/perf.cpp)
target_include_directories(turtle-submission-cycles PRIVATE src)
target_compile_options(turtle-submission-cycles PRIVATE -Wall -Wextra -Wpedantic)
if(TURTLE_WITH_PMU STREQUAL "OFF" OR NOT TURTLE_PMU_INTERFACE)
    target_compile_definitions(turtle-submission-cycles PRIVATE TURTLE_NO_PMU)
endif()

foreach(role client server)
    add_library(turtle-submission-${role} OBJECT src/submission/role.cpp)
    target_include_directories(turtle-submission-${role} PRIVATE src/include src)
    target_compile_options(turtle-submission-${role} PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_definitions(turtle-submission-${role} PRIVATE TURTLE_SUBMISSION_SERVER=$<STREQUAL:${role},server>)
endforeach()

set(submission_objects "")
foreach(part client server cycles)
    set(object "${CMAKE_CURRENT_BINARY_DIR}/submission-${part}.o")
    add_custom_command(OUTPUT "${object}"
        COMMAND "${CMAKE_COMMAND}" -E copy "$<TARGET_OBJECTS:turtle-submission-${part}>" "${object}"
        DEPENDS turtle-submission-${part} $<TARGET_OBJECTS:turtle-submission-${part}>
        VERBATIM)
    list(APPEND submission_objects "${object}")
endforeach()
add_custom_target(turtle-submission-roles ALL DEPENDS ${submission_objects})

add_executable(turtle-submission-job src/submission/job.cpp src/submission/network.cpp)
target_include_directories(turtle-submission-job PRIVATE src)
target_compile_options(turtle-submission-job PRIVATE -Wall -Wextra -Wpedantic)
configure_file(tools/issue-test-leaves.sh turtle-issue-test-leaves.sh COPYONLY)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    option(BUILD_TESTING "Build the TURTLE tests" OFF)
    if(BUILD_TESTING)
        if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
            message(FATAL_ERROR "BUILD_TESTING=ON requires tests/CMakeLists.txt. Use -DBUILD_TESTING=OFF to build without tests.")
        endif()
        include(CTest)
        add_subdirectory(tests)
    endif()
endif()
