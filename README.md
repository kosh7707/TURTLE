# TURTLE

TURTLE measures TLS 1.3 handshakes and application data exchanges on Linux. It builds a client and a server from the same TLS source, then records elapsed time and, when available, CPU cycles on the side you choose.

## Quickstart

| Tools | When you need them |
|---|---|
| C compiler, C++20 compiler, CMake 3.20+, Make or Ninja | Build TURTLE on Linux. |
| `pkg-config` and GNU binutils (`readelf`) | Link the client and server against the submitted TLS library and inspect the resulting binaries. |
| GNU tar, GNU coreutils, `cmp` (diffutils), util-linux (`flock`, `setsid`) | Build a submission or rerun it with `--run-from`. |
| Perl and `make` | Build the OpenSSL source in this example, even if TURTLE uses Ninja. |
| OpenSSL 3.0+ CLI on `PATH` (`openssl req -noenc`) | Generate test certificates. Skip this if you [supply certificates with `--credentials`](docs/submission.md#running-a-benchmark). |
| `curl` (download), `gzip` (extraction) | Prepare the OpenSSL source. A local archive skips the download; an unpacked source tree skips both steps. |

This quickstart does not require system OpenSSL development headers, an external JSON library, or `jq`.

Run the blocks from the repository root in the same shell. If you have an archive of the pinned commit, copy it to `"$archive"` instead of downloading it. If the source is already unpacked in `implementations/openssl/`, run only `work=$(mktemp -d)` from this first block.

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
