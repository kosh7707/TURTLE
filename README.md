# TURTLE

Benchmark a TLS 1.3 implementation on Linux. Supply its source and a small bridge; TURTLE builds both the client and the server, connects them over a virtual Ethernet link (`veth`), and measures **one side per connection**.

## Quickstart

| Needed for | Tools |
|---|---|
| Building TURTLE and linking the submitted library | C++20 compiler, CMake 3.20+, Make or Ninja, pkg-config, GNU binutils and coreutils, GNU tar, util-linux |
| Building OpenSSL in this example | C compiler, Perl, Make; curl and gzip if downloading the source |
| Running the benchmark | Linux network namespaces, veth and netem; `unshare`, `ip`, `tc`, `ping`. An ordinary user needs permission to create user namespaces. There is no loopback fallback. |
| Issuing temporary test certificates | OpenSSL 3.0+ command line, or supply certificates with `--credentials DIR` |

From the repository root, prepare the pinned OpenSSL source. If you already have this source in `implementations/openssl/`, skip the download and extraction.

```sh
work=$(mktemp -d)
curl -fL -o "$work/openssl.tar.gz" https://codeload.github.com/openssl/openssl/tar.gz/2d1c10a592677ff34cdf60bd59c431d835a1fc26 &&
  mkdir implementations/openssl &&
  tar -xzf "$work/openssl.tar.gz" --strip-components=1 -C implementations/openssl
```

Select the example bridge, build both roles, and measure the client's handshake. The build can take several minutes. The five warm-up connections do not count toward the three requested samples.

```sh
tools/init-submission-example.sh openssl &&
  ./bench.sh --build-only --out "$work/build" &&
  ./bench.sh --run-from "$work/build" --out "$work/s0" \
    --scenario S0 --role client --auth server --repetitions 3
cat "$work/s0/cases.csv"
awk -F, 'NR==1 || $4=="sample" {print $4, $5, $7, $9, $10, $11, $12}' "$work/s0/results.csv"
```

The last command shows the phase, attempt, status, elapsed nanoseconds, wall-time status, CPU cycles and counter status. **Blank is not zero:** unavailable counters do not invalidate a verified wall time. If a case did not pass, read its reason in `cases.csv` and the two role logs in the indicated case directory.

## Choose the experiment

| Option | Choices | Default |
|---|---|---|
| `--scenario` | S0 handshake; S1 client request; S2 server-first greeting; S3 request/reply; S4 greeting plus request/reply; or `all` | S3 |
| `--role` | `client`, `server`, or `both` (separate cases, never simultaneous instrumentation) | client |
| `--auth` | `server`, `mtls`, or `both` | server |
| `--rtt-ms`, `--loss-pct` | Added round-trip delay and per-direction packet-loss probability, alone or together | 0 ms, 0% on the same veth |
| `--warmups`, `--repetitions` | Full-task warm-ups and subsequent **attempts**, each at least 1 | 5, 2 |

Reuse the **same linked build** for a different question: how long does it take the server to handle a request and send the reply with mutual authentication, 20 ms added RTT and 1% loss?

```sh
./bench.sh --run-from "$work/build" --out "$work/s3" --scenario S3 --role server \
  --auth mtls --rtt-ms 20 --loss-pct 1 --repetitions 100
cat "$work/s3/cases.csv" "$work/s3/runs/mtls-S3-server/network.csv"
```

[Port a TLS implementation and read the measurements](docs/submission.md) · [Choose a library example](docs/examples/submissions/README.md) · `./bench.sh --help`
