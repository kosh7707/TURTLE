#include "client.hpp"

#include <iostream>

namespace client {
Context configure_tls() {
    Context ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    check_tls(ctx != nullptr, "create client TLS context");
    use_tls13(ctx.get());
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    check_tls(SSL_CTX_load_verify_locations(ctx.get(), cert_path("server.crt").c_str(), nullptr) == 1,
              "load trusted server.crt");
    return ctx;
}

Socket connect_tcp(std::uint16_t port) {
    const auto address = loopback(port);
    Socket peer(check_socket(::socket(AF_INET, SOCK_STREAM, 0), "socket"));
    check_socket(::connect(peer.fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)), "connect");
    return peer;
}

void handshake(SSL* ssl) {
    check_tls(SSL_set_tlsext_host_name(ssl, "localhost") == 1, "set SNI");
    check_tls(SSL_set1_host(ssl, "localhost") == 1, "set expected server name");
    check_tls(SSL_connect(ssl) == 1, "TLS client handshake failed");
    std::cerr << "Connected: " << SSL_get_version(ssl) << '\n';
}
} // namespace client
