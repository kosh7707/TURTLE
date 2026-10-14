cmake_minimum_required(VERSION 3.20)
project(turtle CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Which implementation under test to build in, like SUPERCOP's
# crypto_*/<primitive>/<implementation> directories.
set(TURTLE_IMPLEMENTATION mock CACHE STRING "directory under implementations/")

file(GLOB TURTLE_IMPL_SOURCES CONFIGURE_DEPENDS
     ${CMAKE_CURRENT_SOURCE_DIR}/implementations/${TURTLE_IMPLEMENTATION}/*.cpp)
if(NOT TURTLE_IMPL_SOURCES)
  message(FATAL_ERROR "no sources in implementations/${TURTLE_IMPLEMENTATION}")
endif()

add_executable(turtle src/main.cpp src/transport/tcp.cpp ${TURTLE_IMPL_SOURCES})
target_include_directories(turtle PRIVATE include src)
