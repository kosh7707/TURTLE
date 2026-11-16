set(wolfssl_source "${TURTLE_DEPS_ROOT}/message-src/wolfssl")
set(wolfssl_build "${TURTLE_DEPS_ROOT}/message-build/wolfssl")
turtle_implementation(wolfssl SOURCES message.c
  INCLUDES "${wolfssl_build}" "${wolfssl_source}"
  LIBRARIES "${wolfssl_build}/libwolfssl.a" m pthread)
