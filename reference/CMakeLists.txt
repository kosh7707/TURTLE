# Vendor dependency is scoped to this executable and never exported.
find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL Crypto)
add_executable(turtle-reference main.cpp)
target_link_libraries(turtle-reference PRIVATE turtle_observe OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(turtle-reference PRIVATE cxx_std_20)
target_compile_options(turtle-reference PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(turtle-reference PROPERTIES INSTALL_RPATH "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}" CXX_EXTENSIONS OFF RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
