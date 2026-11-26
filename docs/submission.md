# Submitting a TLS implementation

Start with the [editable recipe and bridge](../implementations/README.md). The supplied pair is inert, not a default TLS implementation. The boundary is a directory, not a pair of prebuilt apps. A developer supplies the native source, its build recipe and one file that implements [the framework declarations](../src/include/turtle/implementation.hpp). TURTLE owns the two mains, the controller and the final link. Neither the upstream TLS project nor the framework core needs to include the other's headers. Only `implementation.cpp` includes both APIs.

## Build boundary

The normative [build contract](build-contract.ko.md) defines executable `implementations/build.sh WORK PREFIX [native arguments...]`, the private SDK it must stage, selection and error handling. The other developer-owned file, `implementations/implementation.cpp`, defines the seven functions below. TURTLE compiles it; the **same selected object** goes into both role links. The [recipes](examples/submissions/README.md) are documentation, not defaults. Use `./bench.sh --build-only` to stop after the two links without starting a doctor, TLS session, or benchmark.

## The runtime interface

| Function | Contract |
|---|---|
| `turtle_tls_setup(config, connected_fd)` / `turtle_tls_free(tls)` | Construct/destroy one fresh TLS 1.3 session. The framework owns the connected socket; borrow it, do not close it. Role, authentication mode, CA, local certificate/key and expected peer DNS name are supplied. Unused fields can be empty. Do not resume a previous session. Fail setup if a required configuration cannot be honored. |
| `turtle_tls_set_hooks(tls, hooks)` | Attach callbacks to the ciphertext transport of this connection; detach on null. A **before-send** callback describes bytes offered, **not** a successful or complete write. An **after-receive** callback describes the bytes actually returned by a positive read. These void callbacks observe; they do not control I/O. Only the selected role is asked to attach them. |
| `turtle_tls_connect(tls)` | Complete the client handshake. Normal application reads before this call must be able to drive a client handshake for S2. |
| `turtle_tls_accept(tls, greeting, len)` | With zero length, complete a normal server handshake. Otherwise send the complete 1-RTT server greeting after the server Finished **without waiting for client Finished**, then complete the handshake. This is not client 0-RTT. If the selected implementation/configuration cannot expose this operation, return `TURTLE_TLS_UNSUPPORTED`; do **not** silently move the write after the handshake. |
| `turtle_app_send(tls, p, len)` / `turtle_app_recv(tls, p, capacity)` | Write/read ordinary plaintext. Return a positive number for progress (short I/O is valid); negative on error, zero on receive EOF. Handle native retry/wait states internally. The framework loops and checks task payloads. |

The framework does not ask for a separate client submission or a TLS-library-specific build rule. Porting the seven functions is real developer work; a library that lacks server-first writes is not made to support them by a successful link.

## One command, from source to results

1. `bench.sh` validates the submission and builds the controller, observation library and two neutral role objects without the stock TLS peer.
2. It invokes the native recipe once for that job, records its log/status, and discovers consumer usage from the staged SDK rather than guessing include paths or library names. It tries the bridge and both actual role link lines. Equivalent candidates collapse to one effective plan. Conflicting or inconclusive candidates stop the job rather than silently selecting one. To resolve an ambiguous choice, run `./bench.sh --resume JOB --use MODULE` with the same native arguments and intended scenario options. Changed inputs/stage require a new job.
3. It links `build/bin/client` and `build/bin/server`, then gives **both explicit executable paths** to `turtle run`. The target/peer selection is independent of the client/server distinction. An unsuccessful native build, link or load cannot fall back to a stock peer.
4. Each requested role/scenario/auth combination gets a distinct doctor: one real execution of that scenario. An operationally ready doctor admits fresh warmup and sample connections, even if some optional observations are missing. Doctor and warmup are never counted as benchmark samples. Each connection is checked against both processes' mapped executable/library paths and the measured role's raw transport events. The staged DSOs' hashes are checked before and after the run. The peer supplies session and app-exchange facts, not a transport trace or performance counters.
5. A case is `passed`, `unsupported`, `failed`, or `insufficient_evidence`. A non-passing requested case gives a nonzero exit, not silent exclusion. An unsupported doctor has no benchmark. Build errors stop earlier and may not produce any summary.

Example, in a populated source checkout:

```sh
job="$HOME/.local/share/turtle/runs/s3"  # must not already exist
./bench.sh --scenario S3 --role client --auth server --warmups 1 --repetitions 5 --out "$job"
jq '.cases[] | {state, doctor: .doctor.state, samples: .benchmark.verified_samples}' "$job/summary.json"
```

`--role both` means **two separate runs**, not a doubly instrumented connection. To exercise all 20 combinations per submission, use `--scenario all --role both --auth both`. `--out` must be new. Without it, the command prints a unique directory under `~/.local/share/turtle/runs/` by default. An absolute `XDG_DATA_HOME` replaces `~/.local/share`; `TURTLE_OUTPUT_DIR` overrides the whole runs path. See the [checkout layout](../README.md#build-and-run-a-submission) for build-cache locations.

Saved reports and transcripts can be read without the framework cache. Saved role **binaries** are not standalone: their loader path names the framework directory that supplied `libturtle_observe.so.1`. If you need to execute those exact binaries later, keep that directory and its observer unchanged at the same path (set `TURTLE_BUILD_DIR` to a persistent directory before building). For a pending job, `--resume` rebuilds and relinks; it does not promise the original observer binary.

```text
JOB/
├── build/
│   ├── native.log, native.exit, work/, prefix/
│   ├── module.txt, implementation.d, client.map, server.map
│   ├── expected-libs.txt, expected-libs.sha256, link-evidence.txt
│   └── bin/{client,server}
├── runs/<authentication>-<scenario>-<measured-role>/
│   ├── doctor/{profile.json,events/,result/analysis.json}
│   └── benchmark/{profile.json,events/,result/analysis.json}
└── summary.json
```

**Runtime success, scenario evidence, and performance qualification answer different questions.** In `turtle.submission-run.v2`, `benchmark.runtime_verified_samples` covers the operational exchange/trace/image checks; `benchmark.verified_samples` also requires the reported TLS session, scenario-specific byte and ordering evidence. `qualified_controller_samples` is the SDK's independent performance qualification. `doctor.verified_connections` can be one while `doctor.verified_samples` is zero. Do not compare a v1 sample count directly to v2.

Under each phase's `evidence[]`, follow the connection ID to the measured CSV, each process's maps and the native attempt (both participants' app streams and event logs). A missing identity, write or timestamp is not proof that TLS failed. Submissions may use the public observer API to report negotiated identity, certificate checks, resumption, app write offers/returns inside a composite accept, and measured-side protocol events. The seven-function submission ABI is unchanged; the generic job does not guess these facts for an opaque implementation or silently replace it. See the [validation report](scenario-validation.ko.md) for a separate diagnostic on exactly the selected bridge.

Each post-task `.maps` snapshot preserves the Linux mapping rows and ends with a `# turtle-maps rows=N` completion marker. Missing, unreadable or incomplete snapshots are insufficient evidence; only a complete snapshot can contradict the expected paths. The row count checks capture completeness, not file identity or authenticity.

The corresponding measured `<UUID>.<role>.csv.count` holds the producer's positive decimal hook-row count and a trailing newline; it excludes the CSV header. It is published only after the detached CSV has been closed and renamed into place. Both files must be complete, with no `.partial` artifacts, before a hook interval is used. A shortened CSV, absent or invalid count, or interrupted publication is insufficient evidence, not a TLS error. Historical raw CSVs without counts are still readable but cannot verify this contract. The unmeasured peer emits neither file.

A CSV span runs from the first **actual** ciphertext hook to the last. It is not a CF latency or a syscall entry/exit pair. Protected messages can share a read; a Finished protocol callback is not a socket send/receive timestamp. For S2, a server greeting write accepted, peer Finished processed and CF ciphertext received are different events. The last of these can be unobservable; neither a composite accept return nor a performance counter fills that gap.

## Supported build and host environment

The submission backend and build prerequisites are specified [here](build-contract.ko.md). For disposable test credentials the controller calls the OpenSSL CLI independently of which TLS library is linked; build-only does not issue credentials. Supply `--credentials DIR` to use existing files instead: `ca.crt`, `server.crt`, `server.key`, and for mTLS also `client.crt` and `client.key` (server DNS name `localhost`, client `client.turtle.test`).

Static-only libraries, arbitrary bare CMake exports without pkg-config metadata, cross-compilation and remote execution are **not** supported by this entry point. Host dependencies of staged DSOs are not all required to live in the prefix. The recorded compiler dependencies and runtime maps tell you which files were used; they do not independently prove that every file supplied on the first install came from the intended configuration. This is a benchmark for cooperating, trusted submissions, not a security attestation.
