#pragma once

#include "endpoint.hpp"

namespace client {
Context configure_tls();    // Trust policy: authenticate the localhost server.
Socket connect_tcp(std::uint16_t port);
void handshake(SSL* ssl);   // Returns on SSL_connect success; throws on failure.
}
