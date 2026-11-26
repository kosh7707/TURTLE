# Example submissions

Choose a recipe for the source you want to measure. TURTLE does not download or choose a TLS library for you. If a fork or different release changes the native API, adapt the recipe and bridge to match.

| Source | Where to put it and what it needs | What the example supports |
|---|---|---|
| [OpenSSL (pinned commit)](https://github.com/openssl/openssl/commit/2d1c10a592677ff34cdf60bd59c431d835a1fc26) | `implementations/openssl/`; Perl and Make | [Recipe](openssl/build.sh) and [bridge](openssl/implementation.cpp). Start with S0 in the [quickstart](../../../README.md#quickstart). Supports S0–S4 with either role measured, with server authentication or mTLS. The measured S2 server identifies the [client Finished read](../../submission.md#scenarios-and-timing-boundaries). |
| [wolfSSL 5.9.4](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.4-stable) | `implementations/wolfssl/`; CMake | The [recipe](wolfssl/build.sh) and [bridge](wolfssl/implementation.cpp) link both roles. The bridge does not support server-first greetings (S2/S4). |
| [GnuTLS 3.8.14](https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.14.tar.xz) | `implementations/gnutls/`; release tarball with `configure`, Make, and development files for nettle, GMP, libtasn1, libidn2, p11-kit and any other dependencies reported by `configure` | The [recipe](gnutls/build.sh) and [bridge](gnutls/implementation.cpp) link both roles. Server-first greetings require GnuTLS early start and are not supported with mTLS. The bridge does not report the S2 server timing endpoint. |
| [Mbed TLS 4.3.0](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.3.0) | `implementations/mbedtls/`; CMake | [library build recipe](mbedtls/build.sh) only; no benchmark bridge. |

Unpack the source directly in the specified directory: for example, GnuTLS's configure script should be at `implementations/gnutls/configure`. For an example that has both a recipe and a bridge, run the following from the TURTLE repository root. Substitute `gnutls` for `wolfssl` to build GnuTLS. The selection tool leaves edited submission files alone.

```sh
job=$(mktemp -d)/build
tools/init-submission-example.sh wolfssl &&
  ./bench.sh --build-only --out "$job"
```

A successful build produces `client` and `server` under `"$job/build/bin/"`. Start with `./bench.sh --run-from "$job" --scenario S0` to measure a handshake. In the run's `cases.csv`, `task_successes` counts completed exchanges; `wall_samples` and `cycle_samples` count verified measurements. See [Results](../../submission.md#results).

To port Mbed TLS, use the `mbedtls-4.3.0.tar.bz2` release asset: it contains subprojects missing from the automatic source snapshot. Verify the release checksum, unpack it under `implementations/mbedtls/`, copy its recipe to `implementations/build.sh`, and [write the bridge](../../submission.md#porting) before running `./bench.sh --build-only`.
