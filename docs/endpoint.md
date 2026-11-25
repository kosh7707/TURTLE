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
- **`read_plain`**: return ordinary application plaintext without waiting to fill the buffer. An S2 client's first TLS call is this read; let it advance TLS internally.

Handle waits and retries inside each callback. On successful I/O, return `TURTLE_OK` with a positive count no greater than the requested length. Partial I/O is normal. Return `TURTLE_CLOSED` for premature EOF, `TURTLE_UNSUPPORTED` for an unavailable operation and `TURTLE_ERROR` for other failures. Unused read/write callbacks may be null.

## Scenario order and timing

The roles run concurrently. Each endpoint SDK sequences its calls and verifies whole messages. Timing starts before the measured role's first TLS call. **H** confirms local handshake completion; **E** reaches the server-first write opportunity.

| Scenario | Client order | Server order | Timing ends: client / server |
|---|---|---|---|
| S0 | H | H | H / H |
| S1 | H → send request | H → verify request | Final request write / full request validation |
| S2 | Read and verify greeting → H | E → send greeting → H | First greeting read / final greeting write |
| S3 | H → send request → read reply | H → verify request → send reply | First reply read / final reply write |
| S4 | H → send **all** request bytes → read greeting and reply | E → send greeting → H → verify request → send reply | First reply read / final reply write |

“First read” means the return delivering the first plaintext byte of that message, not ciphertext arrival. “Final write” means the return accepting its last byte. In S3/S4 the server must validate the **entire request** before writing any reply.

For a qualified sample, attach a socket or TLS-library I/O hook on the **measured role** before calling the SDK. Keep both directions covered through the measured end. Report actual call intervals, direction, requested length and result via the [observation API](../include/turtle/observe.h). A hook reveals record boundaries, not individual messages within an encrypted flight.
