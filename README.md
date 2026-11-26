# TURTLE

TURTLE measures TLS 1.3 handshakes and application data exchanges on Linux. It builds a client and a server from the same TLS source, then records elapsed time and, when available, CPU cycles on the side you choose.

## Quickstart

**Tools:** a C compiler, a C++20 compiler, CMake 3.20 or newer, Make or Ninja, `pkg-config`, GNU tar, coreutils and binutils, and util-linux (`flock`, `setsid`). The OpenSSL example also needs Perl and Make to build the library. To issue test certificates, TURTLE uses the `openssl` CLI on `PATH` (OpenSSL 3.0 or newer, with `req -noenc`). This path does not need system OpenSSL development headers, an external JSON library, or `jq`.

Run the following blocks from the repository root in the same shell. Use `curl` to download the example source, or copy an archive of the same commit to `"$archive"` instead of the download step. If the source is already in `implementations/openssl/`, run only `work=$(mktemp -d)` from this first block.

```sh
work=$(mktemp -d)
archive="$work/openssl.tar.gz"
curl -fL -o "$archive" https://codeload.github.com/openssl/openssl/tar.gz/2d1c10a592677ff34cdf60bd59c431d835a1fc26 &&
  mkdir implementations/openssl &&
  tar -xf "$archive" --strip-components=1 -C implementations/openssl
```

Build both roles, then collect one client sample for S0 (handshake only):

```sh
tools/init-submission-example.sh openssl &&
  ./bench.sh --build-only --out "$work/build" &&
  ./bench.sh --run-from "$work/build" --scenario S0 --role client \
    --auth server --warmups 0 --repetitions 1 --out "$work/s0" &&
  cat "$work/s0/cases.csv" &&
  cut -d, -f1-13 "$work/s0/results.csv"
```

A `cases.csv` row starting with `server,S0,client,passed,1,1` means the one requested sample was verified. In `results.csv`, read the `purpose=sample` row for the measurement; `purpose=doctor` is the preliminary check on a different connection. `wall_ns` is elapsed time in nanoseconds and `cycles` counts CPU cycles on the measured thread. **A blank measurement is unavailable, not zero.** For a failed case, read its `reason` in `cases.csv`. For a native build failure, start with `"$work/build/build/native.log"`.

## Reuse the build

Run a request and response (S3) without rebuilding TLS. Leave the build directory in place and choose an output directory that does not yet exist.

```sh
./bench.sh --run-from "$work/build" --scenario S3 --role client \
  --auth server --warmups 0 --repetitions 1 --out "$work/s3" &&
  cat "$work/s3/cases.csv"
```

- [Port a TLS implementation, check timing boundaries, and read the CSV files](docs/submission.md)
- [Choose an example recipe and bridge](docs/examples/submissions/README.md)
- [Instrument an existing TLS application with the SDK](docs/sdk-guide.md)

Run `./bench.sh --help` for all options.
