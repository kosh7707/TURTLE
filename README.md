# TURTLE

Measure one side of a TLS 1.3 connection on Linux. The default entry point builds **both** roles from the TLS implementation you submit. Pick the client or server to measure; the other executable from the same build is its peer.

## Build and run a submission

**Upgrading an existing checkout?** Older versions ignored `implementations/build.sh` and `implementation.cpp`. A normal pull or branch switch can replace those local files **even when `git status` is clean**. Before updating, use a new checkout or back up and verify both files outside this tree. For an in-place fast-forward, use `git fetch && git merge --ff-only --no-overwrite-ignore '@{upstream}'`; stop if Git refuses. [Upgrade instructions (한국어)](implementations/README.md#기존-작업-트리를-업데이트한다면).

```text
TURTLE/
├── src/                 framework and public headers (src/include/turtle/)
├── tests/               regression and integration tests
├── tools/               build tools, validation, and optional reference peer
├── docs/                contracts, worked examples, and validation report
└── implementations/
    ├── <your-source-tree>/  (you choose the name; TURTLE does not inspect it)
    ├── build.sh             (build and stage the native library)
    └── implementation.cpp   (implement TURTLE's declarations)
```

**First time here? [첫 제출 안내 (한국어)](implementations/README.md).** You get two editable starters: [the build recipe](implementations/build.sh) and [the seven-function bridge](implementations/implementation.cpp). Supply your native source tree and edit both files. With either untouched, `./bench.sh` tells you what is missing and exits 2 **before** building or creating results; the starters do not simulate TLS.

Already have an OpenSSL source tree at `implementations/openssl/`? Run `tools/init-submission-example.sh openssl` to select that [example](docs/examples/submissions/README.md) instead of writing both files. It refuses to replace your edits and never downloads or modifies the native source. For another library use the [build contract](docs/build-contract.ko.md); no vendor registration is needed.

From a populated checkout, check the build without opening a connection:

```sh
./bench.sh --build-only
```

The printed results directory contains `build/bin/client` and `build/bin/server`, not a benchmark report. To benchmark, run `./bench.sh` directly (no prior build needed), or pass that directory to `./bench.sh --resume`. The default is S3 client, one doctor, one warmup and two samples. See [runtime contract and results](docs/submission.md). To select both roles explicitly:

```sh
./bench.sh --scenario S3 --role both --auth mtls --repetitions 10
```

By default, runs go under `~/.local/share/turtle/runs/`; each checkout has a separate framework build under `~/.cache/turtle/`. Absolute `XDG_DATA_HOME` and `XDG_CACHE_HOME` replace those base directories. Use `--out NEW_DIRECTORY` for a named run, or set `TURTLE_OUTPUT_DIR` and `TURTLE_BUILD_DIR` explicitly. Existing jobs stay where they are.

Source-tree consumers that used `-I<checkout>/include` should now use `-I<checkout>/src/include`. Installed SDK headers still live under `include/turtle/`; the `#include <turtle/…>` names and CMake targets are unchanged.

## Alternative: measure a separately built SDK application

These [client](docs/examples/openssl-client-s0.json) and [server](docs/examples/openssl-server-s0.json) profiles measure **full handshake latency** (S0): TLS 1.3, X25519, server authentication, loopback. The measured executable is a [standalone C app](tests/endpoint-integration/consumer.c) linked to OpenSSL, **not** TURTLE's reference peer. Each role runs one warmup and ten measured connections.

You need Linux, Git, CMake 3.20+, C11/C++20 compilers, Make or Ninja, GNU `sha256sum`, and OpenSSL 3.5+ headers, libraries and CLI. The following SDK walkthrough uses a pinned release, not the editable starter slot above. Run in one shell:

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

## Use your own already-built app with a profile

In this explicit profile mode, keep the app's existing build. Link `turtle::endpoint`, supply the [callbacks and transport hooks](docs/endpoint.md), and set `target.argv` to your command. This path does not use the submission directory. A [plain stdin/stdout app](docs/examples/one-sided-s3.json) can run without the SDK but cannot supply missing TLS timings.

Set `scenario` to one of the [five tasks (S0–S4)](docs/endpoint.md#tasks) and `auth` to `server` or `mtls`. The [message abbreviations](docs/endpoint.md#message-abbreviations) are shared by all five tasks. For S1–S4 performance use your app's normal I/O: the example limits application reads and writes to two bytes; S0 uses neither. For an impaired network, e.g. 16 ms added RTT and 20% client-to-server loss, add `"network":"netem","netem":{"additional_rtt_ms":16,"client_to_server":{"loss_pct":20}}` on a host with network-namespace and netem permissions.

## Design decisions

Start with the [build and S0–S4 validation report (한국어)](docs/scenario-validation.ko.md) for reproducible commands, the 20-case matrix, and the path to each connection. The [assignment](task.md) defines the gates; the [build-study migration](docs/build-study-migration.ko.md) and [handoff](docs/handoff/README.ko.md) preserve their provenance. The [decision log](docs/design-decisions.md) records older discussions; it is not the current build contract.
