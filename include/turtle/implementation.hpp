#pragma once

// Functions every TLS implementation under test must define, the way SUPERCOP
// declares crypto_* prototypes and implementers supply the bodies. The
// framework owns the lifecycle and calls these in a fixed order.

namespace turtle {

enum class Role { Client, Server };

enum class Step { WantRead, WantWrite, Done, Failed };

// Result of verifying the peer's certificate chain. NotApplicable only when
// the peer sent no certificate (a server without client authentication).
enum class Verification { Passed, Failed, NotApplicable };

// Per-connection state, defined by the implementation.
struct Connection;

namespace impl {

const char* name();
void setup(Role role);                     // once per fresh measurement process: init, keys, config
// `socket` is an established TCP connection. The framework creates it before
// this call and closes it after close(); the implementation must not close it.
Connection* open(Role role, int socket);   // new connection, before the first TLS byte
Step handshake_step(Connection* conn);     // advance the handshake as far as it can go now
Verification peer_verification(Connection* conn);  // the library's own verification result
bool exchange_app_data(Connection* conn);  // one encrypted message each way
void close(Connection* conn);
void teardown(Role role);                  // once per process

}  // namespace impl
}  // namespace turtle
