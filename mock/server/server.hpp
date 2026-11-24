#pragma once

#include "endpoint.hpp"

namespace server {
Context configure_tls();    // Present the server identity; this mock does not request a client cert.
Socket listen_tcp(std::uint16_t port);
Socket accept_tcp(const Socket& listener);
void handshake(SSL* ssl);   // Returns after SSL_accept completes, not at Server Finished.
}
