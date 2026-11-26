# Add the SDK to an existing TLS application

Keep your application's own build system and use TURTLE to measure one TLS executable. If TURTLE should build both roles from your TLS source instead, follow the [submission quickstart](../README.md#quickstart).

## Install the SDK and check the connection

Run the commands below from the repository root in the same shell. In addition to the [basic build tools](../README.md#quickstart), this example needs the OpenSSL 3.5 or newer development package to build the reference peer, and the `openssl` CLI. Omit `-DTURTLE_BUILD_REFERENCE=ON` only if your profile supplies its own peer.

```sh
work=$(mktemp -d)
cmake -S . -B "$work/build" -DCMAKE_BUILD_TYPE=Release -DTURTLE_BUILD_REFERENCE=ON &&
cmake --build "$work/build" --parallel 2 &&
cmake --install "$work/build" --prefix "$work/sdk"
```

Run the [S0 profile](examples/openssl-client-s0.json) with `openssl s_client`. It makes a TLS 1.3 connection and checks the server certificate and hostname. The client does not use the SDK, so this check produces **no qualified benchmark samples**.

```sh
turtle="$work/sdk/bin/turtle"
profile=docs/examples/openssl-client-s0.json
"$turtle" check "$profile" &&
"$turtle" run "$profile" "$work/s0" &&
cat "$work/s0/attempt-1/client.stderr"
```

`check` validates the configuration; it does not open a connection. After `run`, look for `Protocol version: TLSv1.3` and `Verification: OK` in the client log. The summary's `task success 0/1` means TURTLE could not verify scenario completion from the client's observations. A zero exit status alone does not prove that a measurement succeeded.

## Instrument your application

Add these lines to your application's CMake build and configure it with `-DCMAKE_PREFIX_PATH="$work/sdk"`:

```cmake
find_package(TURTLE CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE turtle::endpoint)
```

Prepare the TCP connection, TLS session, and authentication settings. Then call the [endpoint API](../src/include/turtle/endpoint.h) once, instead of making the first TLS call yourself:

```c
#include <turtle/endpoint.h>

const turtle_endpoint endpoint = {session, handshake_until, write_plain, read_plain};
turtle_result result = turtle_run_endpoint(&endpoint);
```

- Your application owns the socket, TLS session, and authentication. Handle retries inside the callbacks and report the actual number of bytes read or written. Distinguish premature EOF (`TURTLE_CLOSED`), an unsupported operation (`TURTLE_UNSUPPORTED`), and an error (`TURTLE_ERROR`). If the S2 or S4 server cannot send the greeting without waiting for Client Finished, return `TURTLE_UNSUPPORTED`.
- The SDK signals readiness, waits for the shared start, drives the scenario, and checks the test plaintext. Do not call the start wait a second time on the same connection. Reserve stdin and stdout for application data; send diagnostics to stderr.
- On the measured endpoint, install [ciphertext I/O hooks](../src/include/turtle/observe.h) in both directions **before** calling `turtle_run_endpoint()` (before READY) and remove them **after** it returns. Mark the coverage window with `turtle_observe_coverage` and record each call's start, end, and actual return value with `turtle_observe_io`. See the [reference implementation](../tools/reference/main.cpp). Before `_exit()`, or if the process keeps running, call `turtle_observe_flush()` once all observations are done, outside the measured interval and without concurrent callbacks.
- A qualified sample does not by itself prove what was negotiated or which peer was authenticated. To require that evidence, report the negotiated identity with `turtle_observe_identity`, the authentication and handshake facts with `turtle_observe_fact`, and the `auth_accepted` event. Add `"required_metrics": ["authentication", "profile"]` to the profile.

## Run your application

Copy the example profile and set `target.role` and `target.argv`. Put each argument in a separate array entry. Relative executable paths containing `/` resolve from the profile's directory; a bare executable name is looked up on `PATH`. TURTLE substitutes `{host}`, `{port}`, `{ca}`, `{cert}`, `{key}`, and `{peer_name}` in the arguments. The server must listen on the supplied host and port. Read the CA, certificate, key, and peer name from the arguments or from `TURTLE_CA`, `TURTLE_CERT`, `TURTLE_KEY`, and `TURTLE_PEER_NAME`. By default, TURTLE issues temporary test certificates with the `openssl` CLI.

Set `peer.argv` to launch your own peer instead of the reference peer. Call `turtle_run_endpoint()` on that peer as well, or report equivalent readiness, handshake completion, and application data observations. Joining the shared start alone does not verify that the peer completed its task. Only the measured role needs ciphertext I/O hooks. Set `scenario` to S0–S4 and `auth` to `server` or `mtls`. Set `warmups` and `repetitions`; each attempt uses a fresh connection. Set the payloads with `application.request`, `application.greeting`, and `application.response`. The [scenario timing boundaries](submission.md#scenarios-and-timing-boundaries) match the submission workflow.

The default network is `loopback`. To add 20 ms of round-trip delay, set `"network": "netem", "netem": {"additional_rtt_ms": 20}` in the profile. This requires permission to create and configure network namespaces, plus `ip`, `tc`, `ethtool`, and `sysctl`.

Run `"$turtle" run PROFILE NEW_OUTPUT` with an output path that does not exist. Read the task-success and qualification counts in the console, then open the `analysis.json` shown on the `Details:` line for per-attempt reasons. Wall-clock timing and PMU counters can be available independently; a missing value is not zero. Each `attempt-N/` directory contains `client.stderr` and `server.stderr`. Use `"$turtle" analyze RUN` to regenerate the analysis without rerunning TLS.
