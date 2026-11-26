# Submit a TLS implementation

Follow the [first-run guide](../README.md) before porting a new TLS implementation. Start with [the two editable files](../implementations/README.md). They are inert, not a simulated TLS implementation. Submit one native source tree, one executable `build.sh`, and one `implementation.cpp`. The [build contract](build-contract.ko.md) describes the private headers, shared libraries and pkg-config information that the recipe stages.

## Porting

| TURTLE owns | The bridge owns |
|---|---|
| Connected socket and its lifetime, both mains, certificates for local tests, role selection, repetitions, inputs and output validation | TLS session construction, TLS version and credentials, peer name and verification, and the library calls on the borrowed socket |
| Timing around normal TLS and application calls; app read/write loops and their events; saving and verifying a selected role's observations | Facts only the TLS library knows (negotiated identity, resume/early data and authentication state); actual ciphertext hooks; the greeting write inside a server-first accept |

Implement the seven functions in [implementation.hpp](../src/include/turtle/implementation.hpp). The [OpenSSL example](examples/submissions/openssl/implementation.cpp) contains an implementation of each step; start with normal S0 and S1/S3 before adding S2/S4.

| Function | Native call → check/report → return |
|---|---|
| `turtle_tls_setup(config, connected_fd)` | Create a fresh TLS 1.3 session, configure the supplied role, CA, DNS peer name and certificate/key for the chosen authentication mode, and use the existing fd. Disable resumption for these tasks. Return a valid session only if setup succeeded; otherwise return null. |
| `turtle_tls_free(tls)` | Free the session and its owned state. Do not close the borrowed fd. |
| `turtle_tls_set_hooks(tls, hooks)` | Attach to both directions at the ciphertext I/O layer. Return `TURTLE_TLS_OK` only if attachment succeeded; detach on null. The non-measured peer does not attach these hooks. |
| `turtle_tls_connect(tls)` | Drive the native client handshake to local success. Once verification succeeds, report the session facts shown below, then return `TURTLE_TLS_OK`. Ordinary reads must also be able to drive the client handshake for S2. |
| `turtle_tls_accept(tls, greeting, len)` | With no greeting, complete a normal server handshake. Otherwise, once the server Finished is sent, write **all** the greeting without waiting for client Finished, then finish locally and report session facts. Report the greeting write attempts and accepted bytes inside this composite call. If this cannot be done in the selected configuration, return `TURTLE_TLS_UNSUPPORTED`, not a greeting after handshaking. This is not client 0-RTT. |
| `turtle_app_send(tls, p, len)` | Call the native application writer; return the positive number actually accepted (a short write is valid) or a negative error. |
| `turtle_app_recv(tls, p, capacity)` | Read plaintext; return the positive number actually read, zero on EOF, or a negative error. Handle retry/wait states inside both I/O functions. |

For example, the [OpenSSL bridge's `finish()`](examples/submissions/openssl/implementation.cpp) calls `turtle_observe_identity`, reports `resumed`, `early_data`, `verify_peer`, `peer_cert_present` and `peer_verified`, then emits `auth_accepted`. Report those facts after checking the native result, not from a guessed configuration. In its [composite server accept](examples/submissions/openssl/implementation.cpp), the bridge offers the greeting using `turtle_observe_plain("write_attempt", …)` and reports only the returned bytes with `turtle_observe_plain_at(…, "write_accepted", …)`. It does not need to add those calls for ordinary writes through the role runner. Unknown facts may leave a task successful but its evidence incomplete.

### One transport hook bundle

Use `coverage` + `transfer_begin` + `transfer_end` from **the same connection thread** if you can report every actual ciphertext call. Start coverage after installing hooks, before TLS; stop after detaching. Pair each call with its actual return: count only bytes actually transferred, and record zero/failure without pretending that the request was sent. Mark coverage incomplete (`active=-1`) when you cannot pair a call. For the OpenSSL example, the BIO callback pairs native entry and return; it does not change the operation or its retry policy. The runner derives both its transport CSV and transfer evidence from this one bundle.

If paired coverage is not possible, use the two legacy callbacks. `before_send` is a request, **not a completed write**, and `after_recv` is the positive read return, **not a packet arrival timestamp**. They can supply a hook trace, but they do not satisfy the SDK's completed-transfer requirement. Do not register both sets. A callback on another thread, overflow or loss makes the trace incomplete.

The [observer](../src/include/turtle/observe.h) records timed events into bounded memory (up to 8192 records and 4 MiB of copied payload per SDK process); no JSON serialization or pipe write is needed during a timed callback. The start barrier may publish preparation evidence **before** TLS, without completing the stream. An orderly exit finalizes the evidence; for long-lived apps or before `_exit()`, use `turtle_observe_flush()` after all observations, outside measurement and without concurrent callbacks. Publication can block; replay requires the final seal described in the [endpoint guide](endpoint.md).

## Running

- Use `--build-only` to verify both role links without a connection; read `build/native.log` for recipe failures. If module **selection** is needed, use `--build-only --resume JOB --use MODULE` with the original native arguments; this is not a way to repeat experiments. See the [build and reuse contract](build-contract.ko.md).
- Use `--run-from BUILD_JOB --out NEW_RUN` with a completed, unmoved build; it creates new run output without reinstalling or relinking your TLS code. The source slot isn't consulted. A populated checkout also supports a single `./bench.sh` invocation that builds and runs.
- Each requested authentication × scenario × role gets one doctor. It checks a real connection before admitting warmups and samples; each starts fresh processes and a new connection. Only the `sample` rows are repetitions. `--role both` runs separate measured roles, not both on one connection. `--scenario all --role both --auth both` requests all 20 cases; a non-passing requested case returns nonzero.
- `--tcp-nodelay on|off` is the policy for **both connected sockets** in the submission path, default `on`. The CSV reports the read-back value on each role. Keep the policy fixed when comparing runs.
- For pre-existing credentials, use `--credentials DIR` with `ca.crt`, `server.crt`, `server.key` and, for mTLS, `client.crt` and `client.key`. Names are `localhost` (server) and `client.turtle.test` (client). Otherwise `openssl` issues disposable test certificates; the command is independent of which TLS library you submit.

| To change… | Use |
|---|---|
| Role, scenario, authentication, repetitions, TCP_NODELAY | Submission run flags; reuse the same build |
| Build options and which features are compiled | Recipe arguments after `--` when building; an altered build gets a new job |
| The TLS group's or cipher suite's session policy | TLS bridge; the submission runner does not set the library's algorithm policy |
| Custom application payloads or network conditions | The [standalone SDK profile](sdk-guide.ko.md); no matching options in the basic submission CLI |

## Results

Open `cases.csv` first. Each row is one authentication × scenario × role: `state`, requested and verified sample counts, operational and performance-qualified counts, and reason or detail path. `passed`, `unsupported`, `failed`, and `insufficient_evidence` are distinct. Build failures stop earlier and may not create a CSV. A successful TLS connection is not proof of a qualified performance measurement.

`results.csv` has **one row per readable, bound attempt**. An unreadable,
missing, or mismatched attempt may produce no row. Use the case's requested
and verified counts and first diagnostic to distinguish missing evidence from
a successful sample; the framework does not invent substitute rows.

| Columns | What to read |
|---|---|
| `purpose`, `connection_id`, `task_success`, `evidence_state` | Filter for `purpose=sample` when comparing repetitions; inspect task outcome and evidence separately. |
| `wall_ns`, `wall_status`, `first_greeting_read_ns`, `greeting_write_accept_ns` | Elapsed ns for the [task's local interval](endpoint.md#tasks), excluding TCP establishment. The S2 client ends at **full** greeting read, with first-read time separate. The S2 server does not claim a CF-receive interval when CF cannot be attributed; greeting write acceptance is separate. |
| `cycles`, `pmu_status`, `performance_qualified`, `qualification_reason` | Cycles for the measured user-space thread and associated interval, not elapsed ns. Empty measurements are unavailable, not zero. A reported wall time does not require PMU, and neither value alone qualifies the sample. |
| `client_tcp_nodelay`, `server_tcp_nodelay`, `evidence_reason`, `client_stderr`, `server_stderr` | Effective socket values and diagnostics. Open stderr paths relative to the **new run** directory. |

The regular submission flow does not require a JSON library or `jq`. Versioned `summary.json`, `profile.json`, `analysis.json` and observer NDJSON still support diagnostics and reanalysis via the project's standard-library parser. Under a run's `runs/<authentication>-<scenario>-<role>/<doctor|benchmark>/`, match the `connection_id` to both endpoint maps, app streams, and the measured role's hook CSV and `.csv.count` (producer row count, excluding the header). Missing or incomplete artifacts do not prove failure or success. The hook CSV's first-to-last span is not a handshake or CF interval. Protected messages can share a read, and a protocol Finished callback is not a socket arrival time. See the [previous verification report](scenario-validation.ko.md) for the distinction between raw timing and the independent server-first capability control.

The build receipt and maps establish which executables and private libraries were used, not whether untrusted code is safe. Use only trusted builds. Static-only or arbitrary bare CMake exports without pkg-config metadata, cross-compilation and remote execution are outside the submission contract.
