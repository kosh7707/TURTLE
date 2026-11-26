# Mbed TLS 4.3.0: native Linux build recipe

This is a **build-only** example. It installs a native SDK; it does not provide an `implementation.cpp`, run a TLS handshake, test an embedded board, or demonstrate post-quantum TLS. It is not a default TURTLE dependency.

To prepare the source from a TURTLE checkout, run these steps before using the recipe. Verify the SHA-256 from the [official 4.3.0 release](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.3.0). Use the named release asset, not GitHub's generic source snapshot: the release includes the required subprojects and pregenerated files.

```sh
mkdir -p implementations
curl --fail --location --output mbedtls-4.3.0.tar.bz2 \
    https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.3.0/mbedtls-4.3.0.tar.bz2
printf '%s\n' '1c87cba094cb40f097ebe0eba440a74939b71dab4e1d0d566bc90749ff381d18  mbedtls-4.3.0.tar.bz2' | sha256sum -c -
mkdir implementations/mbedtls
tar -xjf mbedtls-4.3.0.tar.bz2 --strip-components=1 -C implementations/mbedtls
```

The recipe expects `./mbedtls` below its working directory. It builds shared libraries using the release's pregenerated sources, without invoking a Python interpreter or downloading during build. It needs a native C compiler, CMake, and the chosen CMake generator's build tool. For a recipe-only check (no `implementation.cpp` required):

```sh
job=$(mktemp -d)
mkdir "$job/work" "$job/prefix"
(cd implementations && ../docs/examples/submissions/mbedtls/build.sh "$job/work" "$job/prefix" -DCMAKE_BUILD_TYPE=Release)
PKG_CONFIG_LIBDIR="$job/prefix/lib/pkgconfig" PKG_CONFIG_PATH= \
    pkg-config --cflags --libs mbedtls-sdk
```

To run `./bench.sh`, opt in to the recipe through the [example catalog](../README.md) and supply your own `implementation.cpp` implementing the [submission interface](../../../submission.md). The recipe-only instructions above do not activate a submission. Native CMake settings after the outer `--` are separate arguments, for example `./bench.sh -- '-DCMAKE_C_FLAGS=-fno-omit-frame-pointer -g0'`. This recipe keeps install paths and shared-library packaging fixed; for customized configuration headers, use `MBEDTLS_CONFIG_BASE_FILE` or `TF_PSA_CRYPTO_CONFIG_BASE_FILE` as supported by the pinned release. The install must expose the same configuration headers the library used. The example does not support upstream's interpreter-driven configuration transforms.

The upstream [`mbedtls.pc` template](https://github.com/Mbed-TLS/mbedtls/blob/eafb4a72592addfd5ba1326caad2f3e9adef49ad/pkgconfig/mbedtls.pc.in#L5-L11) lists X.509 and crypto as private dependencies. The original module linked a consumer using only the TLS API. It did not link a mixed TLS/X.509/PSA consumer: the linker reported that the X.509 DSO was missing from the command line. The recipe adds one aggregate, `mbedtls-sdk.pc`, using `Requires` to reuse installed modules, without duplicating include paths or library flags. The same mixed consumer then linked, loaded all three private DSOs and initialized their public APIs. A separate link-only fixture exercised the generic TURTLE builder. Neither test is a benchmark result.

## Post-quantum scope

Do not infer protocol support from a crypto primitive. The bundled [TF-PSA-Crypto 1.3.0 release notes](https://github.com/Mbed-TLS/TF-PSA-Crypto/releases/tag/tf-psa-crypto-1.3.0) describe experimental ML-DSA at the driver-dispatch layer, not an application API. The pinned [TLS named-group implementation](https://github.com/Mbed-TLS/mbedtls/blob/eafb4a72592addfd5ba1326caad2f3e9adef49ad/library/ssl_tls.c#L2422-L2467) and [TLS group declarations](https://github.com/Mbed-TLS/mbedtls/blob/eafb4a72592addfd5ba1326caad2f3e9adef49ad/include/mbedtls/ssl.h#L4004-L4019) do not expose ML-KEM or a hybrid ML-KEM group. Treat this pinned build as an Mbed TLS build example, **not** an upstream PQTLS support claim or a claim about other versions and forks.
