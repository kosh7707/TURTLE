#pragma once

#include <cstdint>
#include <string>

namespace turtle::tcp {

struct Listener {
    int fd;
    std::uint16_t port;
};

// All sockets are on the loopback interface for now.
Listener listen_loopback();
int accept_one(int listen_fd);
int connect_loopback(std::uint16_t port);

// Empty if `fd` is an established TCP connection with nothing unread;
// otherwise the reason it is not ready for a TLS handshake.
std::string check_ready(int fd);

} // namespace turtle::tcp
