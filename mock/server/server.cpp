#include "server.hpp"

#include <iostream>

namespace server {
Context configure_tls() {
    Context ctx(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    check_tls(ctx != nullptr, "create server TLS context");
    use_tls13(ctx.get());
    check_tls(SSL_CTX_use_certificate_chain_file(ctx.get(), cert_path("server.crt").c_str()) == 1,
              "load server.crt");
    check_tls(SSL_CTX_use_PrivateKey_file(ctx.get(), cert_path("server.key").c_str(), SSL_FILETYPE_PEM) == 1,
              "load server.key");
    check_tls(SSL_CTX_check_private_key(ctx.get()) == 1, "match certificate and key");
    return ctx;
}

Socket listen_tcp(std::uint16_t port) {
    auto address = loopback(port);
    Socket listener(check_socket(::socket(AF_INET, SOCK_STREAM, 0), "socket"));
    const int reuse = 1;
    check_socket(::setsockopt(listener.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)), "setsockopt");
    check_socket(::bind(listener.fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)), "bind");
    check_socket(::listen(listener.fd, 1), "listen");
    socklen_t length = sizeof(address);
    check_socket(::getsockname(listener.fd, reinterpret_cast<sockaddr*>(&address), &length), "getsockname");
    std::cout << "Listening on 127.0.0.1:" << ntohs(address.sin_port) << std::endl;
    return listener;
}

Socket accept_tcp(const Socket& listener) {
    int fd;
    do { fd = ::accept(listener.fd, nullptr, nullptr); } while (fd < 0 && errno == EINTR);
    return Socket(check_socket(fd, "accept"));
}

void handshake(SSL* ssl) {
    check_tls(SSL_accept(ssl) == 1, "TLS server handshake failed");
    std::cerr << "Connected: " << SSL_get_version(ssl) << '\n';
}
} // namespace server
