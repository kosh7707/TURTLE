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

// Numeric IPv4 in the caller's network namespace; port 0 requests a dynamic port.
Listener listen_ipv4(const std::string& address, std::uint16_t port = 0);
Endpoint local_endpoint(int fd);
Endpoint peer_endpoint(int fd);

// Prepared before the trial; owns no descriptors. The role runtime owns the
// listener and each newly created connection. Completion is nonblocking.
struct DialAddress {
    std::uint32_t source = 0;
    std::uint32_t target = 0;
    std::uint16_t port = 0;
};
DialAddress prepare_dial(const std::string& source, const Endpoint& target);
int begin_connect(const DialAddress& address);
void finish_connect(int fd);
void nonblocking_listener(int fd);
int try_accept(int listener); // -1 means retry after readability

// Empty if `fd` is an established TCP connection with nothing unread;
// otherwise the reason it is not ready for a TLS handshake.
std::string check_ready(int fd);

// Snapshot only fields supported by the returned Linux TCP_INFO structure.
// Unsupported/missing values remain null with a note; observed zero stays 0.
model::TcpInfoSnapshot read_tcp_info(int fd) noexcept;

} // namespace turtle::tcp
