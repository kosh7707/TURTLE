find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
add_executable(turtle_interpret_test interpret_test.cpp)
target_link_libraries(turtle_interpret_test PRIVATE turtle_interpret OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME interpret_real_tls COMMAND turtle_interpret_test)
