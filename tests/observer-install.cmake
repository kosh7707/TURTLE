# An application with no C++ compiler, framework sources or TLS library dependency.
cmake_minimum_required(VERSION 3.20)
file(MAKE_DIRECTORY "${WORK}/app")
execute_process(COMMAND "${CMAKE_COMMAND}" --install "${BUILD}" --prefix "${WORK}/sdk" COMMAND_ERROR_IS_FATAL ANY)
file(WRITE "${WORK}/app/main.c" [=[
#include <turtle/observe.h>
int main(void) {
    turtle_observe_event("ready");
    (void)turtle_observe_now(); return 0;
}
]=])
file(WRITE "${WORK}/app/CMakeLists.txt" [=[
cmake_minimum_required(VERSION 3.20)
project(application LANGUAGES C)
find_package(TURTLE REQUIRED CONFIG)
add_executable(application main.c)
target_link_libraries(application PRIVATE turtle::observe)
]=])
execute_process(COMMAND "${CMAKE_COMMAND}" -S "${WORK}/app" -B "${WORK}/consumer" "-DCMAKE_PREFIX_PATH=${WORK}/sdk" COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${WORK}/consumer" COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${WORK}/consumer/application" COMMAND_ERROR_IS_FATAL ANY)
