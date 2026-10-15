#pragma once

#include <cstdint>
#include <string>

#include "model/model.hpp"

namespace turtle::tcp {

struct Listener {
    int fd;
    std::uint16_t port;
};

struct Endpoint {
    std::string address;
    std::uint16_t port = 0;
};

// All sockets are on the loopback interface for now.
Listener listen_loopback();
int accept_one(int listen_fd);
int connect_loopback(std::uint16_t port);

// Namespace-aware paths. The caller enters the supplied namespace before
// calling these functions. address is an IPv4 numeric address; port 0 requests
// a dynamic listener port. connect_ipv4 binds source_address explicitly.
Listener listen_ipv4(const std::string& address, std::uint16_t port = 0);
int connect_ipv4(const std::string& source_address, const Endpoint& destination);
Endpoint local_endpoint(int fd);
Endpoint peer_endpoint(int fd);

// Empty if `fd` is an established TCP connection with nothing unread;
// otherwise the reason it is not ready for a TLS handshake.
std::string check_ready(int fd);

// Snapshot only fields supported by the returned Linux TCP_INFO structure.
// Unsupported/missing values remain null with a note; observed zero stays 0.
model::TcpInfoSnapshot read_tcp_info(int fd) noexcept;

} // namespace turtle::tcp
