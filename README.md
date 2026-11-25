# TURTLE

Measure one side of a TLS 1.3 connection on Linux. You supply a client **or** server; TURTLE supplies the other role and records the selected task's latency and hardware counters.

## Benchmark OpenSSL

These [client](docs/examples/openssl-client-s0.json) and [server](docs/examples/openssl-server-s0.json) profiles measure **full handshake latency** (S0): TLS 1.3, X25519, server authentication, loopback. The measured executable is a [standalone C app](tests/endpoint-integration/consumer.c) linked to OpenSSL, **not** TURTLE's reference peer. Each role runs one warmup and ten measured connections.

You need Linux, Git, CMake 3.20+, C11/C++20 compilers, Make or Ninja, GNU `sha256sum`, and OpenSSL 3.5+ headers, libraries and CLI. Run in one shell:

```sh
git clone --depth 1 --branch v1.0.0 https://github.com/kosh7707/TURTLE.git
cd TURTLE
work=$(mktemp -d)
```

<details>
<summary>System OpenSSL older than 3.5?</summary>

Build the pinned version locally (requires Perl and Make); leave the system installation alone.

```sh
cmake -DNAME=openssl -DVERSION=3.5.9 -P tools/dependencies.cmake
export OPENSSL_ROOT_DIR="$PWD/.deps/prepared/openssl-3.5.9/install"
export PATH="$OPENSSL_ROOT_DIR/bin:$PATH"
export LD_LIBRARY_PATH="$OPENSSL_ROOT_DIR/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

</details>

```sh
# Skip the download if nlohmann_json 3.12+ is already installed.
cmake -DNAME=json -DVERSION=3.12.0 -P tools/dependencies.cmake
cmake -S . -B "$work/turtle" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build "$work/turtle" --parallel 2
cmake --install "$work/turtle" --prefix "$work/sdk"

# The measured app uses its own build, against the installed SDK.
cmake -S tests/endpoint-integration -B "$work/app" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$work/sdk"
cmake --build "$work/app" --parallel 2
export PATH="$work/app:$PATH"

for role in client server; do
  "$work/sdk/bin/turtle" run "docs/examples/openssl-$role-s0.json" "$work/$role-s0"
done
printf 'Results: %s\n' "$work"
```

## Read the result

**Task success and sample qualification are separate.** A host that denies hardware-counter access can complete all ten handshakes but qualify none. The CLI gives the exclusion reason. Its example duration is one connection, not an average.

With `jq`, print the qualifying client samples as **attempt, wall milliseconds, user-space thread cycles, instructions**. No rows means no qualified samples. S0 spans the first local TLS call to successful handshake return; it excludes TCP setup.

```sh
jq -r '.measured_role as $r | .attempts[] | select(.purpose == "sample" and .qualified) |
  .participants[$r].timing.pmu_delta as $cpu |
  [.directory, (.benchmark_timing_ns / 1000000), $cpu.cycles, $cpu.instructions] | @tsv' \
  "$work/client-s0/analysis.json"
```

Keep the whole result directory. Replay without launching TLS: `"$work/sdk/bin/turtle" analyze "$work/client-s0"`.

## Use your own app

Keep its existing build. Link `turtle::endpoint`, supply the [callbacks and transport hooks](docs/endpoint.md), and set `target.argv` to your command. There is no `implementations/` directory to populate. A [plain stdin/stdout app](docs/examples/one-sided-s3.json) can run without the SDK but cannot supply missing TLS timings.

Set `scenario` to one of the [five tasks (S0–S4)](docs/endpoint.md#tasks) and `auth` to `server` or `mtls`. The [message abbreviations](docs/endpoint.md#message-abbreviations) are shared by all five tasks. For S1–S4 performance use your app's normal I/O: the example limits application reads and writes to two bytes; S0 uses neither. For an impaired network, e.g. 16 ms added RTT and 20% client-to-server loss, add `"network":"netem","netem":{"additional_rtt_ms":16,"client_to_server":{"loss_pct":20}}` on a host with network-namespace and netem permissions.
