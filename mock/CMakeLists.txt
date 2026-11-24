cmake_minimum_required(VERSION 3.20)
project(openssl_chat LANGUAGES CXX)

if(NOT UNIX)
    message(FATAL_ERROR "This terminal chat uses POSIX sockets and poll().")
endif()
find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
find_program(OPENSSL_CLI NAMES openssl REQUIRED)

# A fresh, local identity for this build; no private key lives in the sources.
set(cert_dir "${CMAKE_CURRENT_BINARY_DIR}/certs")
file(MAKE_DIRECTORY "${cert_dir}")
file(CHMOD "${cert_dir}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
add_custom_command(
    OUTPUT "${cert_dir}/server.crt" "${cert_dir}/server.key"
    COMMAND "${OPENSSL_CLI}" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256
        -sha256 -noenc -batch -days 30 -subj "/CN=localhost"
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
        -addext "basicConstraints=critical,CA:FALSE"
        -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=serverAuth"
        -keyout "${cert_dir}/server.key" -out "${cert_dir}/server.crt"
    COMMENT "Generating a localhost-only demo certificate" VERBATIM)
add_custom_target(chat_identity DEPENDS "${cert_dir}/server.crt" "${cert_dir}/server.key")

add_library(chat_session STATIC chat.cpp)
target_compile_features(chat_session PUBLIC cxx_std_17)
target_include_directories(chat_session PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(chat_session PUBLIC OpenSSL::SSL OpenSSL::Crypto)

foreach(role IN ITEMS server client)
    add_executable(chat_${role} ${role}/main.cpp ${role}/${role}.cpp)
    target_compile_definitions(chat_${role} PRIVATE "CHAT_CERT_DIR=\"${cert_dir}\"")
    target_link_libraries(chat_${role} PRIVATE chat_session)
    add_dependencies(chat_${role} chat_identity)
endforeach()

include(CTest)
if(BUILD_TESTING)
    add_test(NAME tls_chat COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/test_chat.sh"
        "$<TARGET_FILE:chat_server>" "$<TARGET_FILE:chat_client>" "${OPENSSL_CLI}")
    set_tests_properties(tls_chat PROPERTIES TIMEOUT 45)
endif()
