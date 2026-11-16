foreach(variant baseline cached)
  set(prefix "${TURTLE_DEPS_ROOT}/message-build/bithac-${variant}")
  set(definitions TURTLE_BACKEND_NAME="bithac-${variant}")
  if(variant STREQUAL "cached")
    list(APPEND definitions TURTLE_BITHAC_CACHED=1 WOLFSSL_CACHED_INFO WOLFSSL_SSC)
  endif()
  turtle_implementation(bithac-${variant} SOURCES ../wolfssl/message.c
    INCLUDES "${prefix}" "${TURTLE_DEPS_ROOT}/message-src/bithac"
    LIBRARIES "${prefix}/libwolfssl.a" m pthread DEFINITIONS ${definitions})
endforeach()
