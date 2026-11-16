set(mbedtls_source "${TURTLE_DEPS_ROOT}/message-src/mbedtls")
set(mbedtls_build "${TURTLE_DEPS_ROOT}/message-build/mbedtls")
turtle_implementation(mbedtls SOURCES message.c
  INCLUDES "${mbedtls_source}/include" "${mbedtls_source}/library"
  LIBRARIES "${mbedtls_build}/library/libmbedtls.a" "${mbedtls_build}/library/libmbedx509.a" "${mbedtls_build}/library/libmbedcrypto.a")
