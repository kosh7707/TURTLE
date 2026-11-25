# Integrate a TLS endpoint

Configure a fresh TCP connection, TLS role, credentials and verification policy in your application. Before the first TLS operation, pass the connection and its callbacks to the [endpoint SDK](../include/turtle/endpoint.h). TURTLE borrows the opaque `conn` for this call; your application owns the session, socket and cleanup.

```c
const turtle_endpoint endpoint = {ssl, handshake, write_plain, read_plain};
turtle_result r = turtle_run_endpoint(&endpoint);
```

In your own CMake project:

```cmake
find_package(TURTLE CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE turtle::endpoint)
```

The [OpenSSL example](../tests/endpoint-integration/consumer.c) implements these callbacks.

## Callbacks

- **`handshake_until`**: for `TURTLE_LOCAL_COMPLETE`, confirm local full-handshake success. S2/S4 servers also need `TURTLE_SERVER_CAN_SEND`: return at the first write opportunity after sending server Finished, without waiting for client Finished.
- **`write_plain`**: report bytes TLS actually accepted. At `TURTLE_SERVER_CAN_SEND`, use the server-first write path; do not queue the greeting or finish the handshake first.
- **`read_plain`**: return ordinary application plaintext without waiting to fill the buffer. The read may advance TLS internally.

Handle waits and retries inside each callback. On successful I/O, return `TURTLE_OK` with a positive count no greater than the requested length. Partial I/O is normal. Return `TURTLE_CLOSED` for premature EOF, `TURTLE_UNSUPPORTED` for an unavailable operation and `TURTLE_ERROR` for other failures. Unused read/write callbacks may be null.

For a qualified sample, attach a socket or TLS-library I/O hook on the **measured role** before calling the SDK. Keep both directions covered through the measured end. Report actual call intervals, direction, requested length and result via the [observation API](../include/turtle/observe.h).

## Message abbreviations

| Symbol | English name | Meaning |
|---|---|---|
| `CH` / `SH` | ClientHello / ServerHello | The client offers handshake parameters; the server selects them. |
| `EE` | EncryptedExtensions | The server sends its encrypted extensions. |
| `CR` | CertificateRequest | The server requests a client certificate in mutual TLS (mTLS). |
| `CC` / `SC` | Certificate | The client / server sends its certificate chain. |
| `CCV` / `SCV` | CertificateVerify | The client / server signs the handshake transcript. |
| `CF` / `SF` | Finished | The client / server sends its handshake transcript integrity check. |
| `CCCS` / `SCCS` | ChangeCipherSpec | Optional client / server compatibility record, not a handshake message. |
| `CAD` | Client Application Data | Client-to-server application payload. |
| `SAD` | Server Application Data | Server-to-client greeting (`SAD₁`) or reply (`SAD₂`); result files use `SAD1` and `SAD2`. |

## Tasks

All five tasks use a fresh, certificate-based TLS 1.3 handshake. With application data omitted, the flows are:

- Server authentication: `CH → SH → SCCS? → [EE, SC, SCV, SF] → CCCS? → CF`
- mTLS: `CH → SH → SCCS? → [EE, CR, SC, SCV, SF] → CCCS? → [CC, CCV, CF]`

`?` means optional. Brackets group protected messages in one direction: a group can span multiple records, and record headers do not give individual message timestamps.

| Symbol | English name | Meaning |
|---|---|---|
| S0 | Handshake only | Complete the handshake; no `CAD` or `SAD`. |
| S1 | Client one-way send | After its handshake the client sends `CAD`. The server validates it and sends no `SAD`. |
| S2 | Server-first greeting | After `SF`, the server sends `SAD₁` without waiting for `CF`; there is no `CAD`. The client starts TLS with a read and validates `SAD₁` before explicitly confirming its local handshake. |
| S3 | Request and reply | No greeting. The client sends `CAD` after its handshake. The server completes its local handshake and validates **all** `CAD` before sending `SAD₂`. |
| S4 | Greeting, request and reply | The server sends `SAD₁` after `SF` without waiting for `CF`, and sends `SAD₂` only after its handshake and full `CAD` validation. After its handshake the client writes **all** `CAD` before reading `SAD₁`, then `SAD₂`. |

A server write does not prove that the client received `SAD₁` before it sent `CF`.

**Timing** starts before the measured role's first TLS call. In S0 it ends at local handshake success; in S1, at final `CAD` write acceptance (client) or full `CAD` validation (server). For S2, S3 and S4, the client ends at the first plaintext read return and the server at final write acceptance for **`SAD₁` in S2** or **`SAD₂` in S3/S4**.
