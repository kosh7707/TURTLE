set(openssl_source "${TURTLE_DEPS_ROOT}/message-src/openssl")
if(NOT EXISTS "${openssl_source}/libssl.a")
  message(FATAL_ERROR "Pinned OpenSSL source build is required; run scripts/build-deps.sh openssl")
endif()
turtle_implementation(openssl SOURCES message.c
  INCLUDES "${openssl_source}" "${openssl_source}/include" "${openssl_source}/ssl"
  LIBRARIES "${openssl_source}/libssl.a" "${openssl_source}/libcrypto.a" dl pthread)
