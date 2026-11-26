# Example submissions

Choose a recipe for the source you want to measure. TURTLE does not download or choose a TLS library for you. If a fork or different release changes the native API, adapt the recipe and bridge to match.

| Source | Where to put it and what it needs | What the example supports |
|---|---|---|
| [OpenSSL (pinned commit)](https://github.com/openssl/openssl/commit/2d1c10a592677ff34cdf60bd59c431d835a1fc26) | `implementations/openssl/`; Perl and Make | [Recipe](openssl/build.sh) and [bridge](openssl/implementation.cpp). Start with S0 in the [quickstart](../../../README.md#quickstart). S0–S4 have been exercised. In S2, the server cannot identify the transport read that received the client's Finished message. |
| [wolfSSL 5.9.4](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.4-stable) | `implementations/wolfssl/`; CMake | The [recipe](wolfssl/build.sh) and [bridge](wolfssl/implementation.cpp) link both roles. The bridge does not support server-first greetings (S2/S4). |
| [GnuTLS 3.8.14](https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.14.tar.xz) | `implementations/gnutls/`; release tarball with `configure`, Make, and development files for nettle, GMP, libtasn1, libidn2, p11-kit and any other dependencies reported by `configure` | The [recipe](gnutls/build.sh) and [bridge](gnutls/implementation.cpp) link both roles. The bridge cannot send a server-first greeting with mutual TLS or without GnuTLS early start. |
| [Mbed TLS 4.3.0](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.3.0) | `implementations/mbedtls/`; CMake | [library build recipe](mbedtls/build.sh) only; no benchmark bridge. |

Unpack the source directly in the specified directory: for example, GnuTLS's configure script should be at `implementations/gnutls/configure`. For an example that has both a recipe and a bridge, run the following from the TURTLE repository root. Substitute `gnutls` for `wolfssl` to build GnuTLS. The selection tool leaves edited submission files alone.

```sh
job=$(mktemp -d)/build
tools/init-submission-example.sh wolfssl &&
  ./bench.sh --build-only --out "$job"
```

A successful build produces `client` and `server` under `"$job/build/bin/"`. To try a TLS connection, run `./bench.sh --run-from "$job" --scenario S0`. With the supplied wolfSSL bridge, a handshake can succeed even when the case reports `insufficient_evidence` and the command exits nonzero. A successful link or handshake alone does not qualify a performance sample. See [Results](../../submission.md#results).

## Build the Mbed TLS libraries only

Download the `mbedtls-4.3.0.tar.bz2` release asset, which includes the required subprojects; do not use GitHub's automatically generated source snapshot. Verify the release checksum, unpack the source into `implementations/mbedtls/`, then run:

```sh
job=$(mktemp -d)
mkdir "$job/work" "$job/prefix" &&
  (cd implementations && ../docs/examples/submissions/mbedtls/build.sh "$job/work" "$job/prefix") &&
  PKG_CONFIG_LIBDIR="$job/prefix/lib/pkgconfig" PKG_CONFIG_PATH= \
    pkg-config --cflags --libs mbedtls-combined
```

This installs the Mbed TLS libraries and headers; it does not build the benchmark roles. To benchmark it, copy the recipe to `implementations/build.sh` and [write the bridge](../../submission.md#porting). The selection tool requires both files and will not install this recipe by itself.
