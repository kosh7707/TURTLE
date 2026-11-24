cmake_minimum_required(VERSION 3.20)
file(READ "${INPUT}" content)
# CMake's JSON reader normally ignores trailing input. Require the appended
# sentinel to be the second element so an entire file is exactly one JSON value.
file(SHA256 "${INPUT}" sentinel)
string(JSON tail GET "[${content}\n,\"${sentinel}\"]" 1)
if(NOT tail STREQUAL sentinel)
    message(FATAL_ERROR "Unexpected content after JSON value in ${INPUT}")
endif()
