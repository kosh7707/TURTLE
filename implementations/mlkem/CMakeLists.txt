foreach(variant c avx2)
  set(prefix "${TURTLE_DEPS_ROOT}/message-build/mlkem-${variant}")
  turtle_implementation(mlkem-${variant} SOURCES ../wolfssl/message.c
    INCLUDES "${prefix}" "${TURTLE_DEPS_ROOT}/message-src/mlkem"
    LIBRARIES "${prefix}/libwolfssl.a" m pthread
    DEFINITIONS TURTLE_MLKEM=1 TURTLE_BACKEND_NAME="mlkem-${variant}")
endforeach()
