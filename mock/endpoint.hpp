#pragma once

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

inline int check_socket(int result, const char* operation) {
    if (result < 0)
        throw std::system_error(errno, std::generic_category(), operation);
    return result;
}

struct Socket {
    explicit Socket(int descriptor) : fd(descriptor) {}
    Socket(Socket&& other) noexcept : fd(std::exchange(other.fd, -1)) {}
    ~Socket() { if (fd >= 0) ::close(fd); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    int fd;
};

inline std::uint16_t port_argument(int argc, char** argv, bool allow_zero) {
    if (argc == 1) return 8443;
    if (argc != 2) throw std::runtime_error("usage: " + std::string(argv[0]) + " [port]");
    std::string_view value(argv[1]);
    std::uint16_t port{};
    const auto end = value.data() + value.size();
    const auto parsed = std::from_chars(value.data(), end, port);
    if (parsed.ec != std::errc{} || parsed.ptr != end || (!allow_zero && port == 0))
        throw std::runtime_error(allow_zero ? "port must be 0..65535" : "port must be 1..65535");
    return port;
}

inline sockaddr_in loopback(std::uint16_t port) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    return address;
}

inline std::string cert_path(const char* name) {
    const char* dir = std::getenv("CHAT_CERT_DIR");
    return std::string(dir && *dir ? dir : CHAT_CERT_DIR) + "/" + name;
}

using Context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using Session = std::unique_ptr<SSL, decltype(&SSL_free)>;

inline void check_tls(bool ok, const char* operation) {
    if (!ok) throw std::runtime_error(operation);
}

inline void use_tls13(SSL_CTX* ctx) {
    check_tls(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
              SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1, "set TLS 1.3");
}

inline Session attach_socket_bio(const Context& ctx, const Socket& peer) {
    Session ssl(SSL_new(ctx.get()), SSL_free);
    check_tls(ssl != nullptr, "create TLS session");
    check_tls(SSL_set_fd(ssl.get(), peer.fd) == 1, "attach socket");
    // A wire observer would attach to the socket BIO here, before the handshake.
    return ssl;
}
