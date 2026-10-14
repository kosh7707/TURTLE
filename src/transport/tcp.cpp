#include "transport/tcp.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <system_error>

namespace turtle::tcp {

namespace {

[[noreturn]] void fail(const char* what, int fd = -1) {
    const int error = errno;
    if (fd >= 0) ::close(fd);
    throw std::system_error(error, std::generic_category(), what);
}

sockaddr_in loopback(std::uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return addr;
}

}  // namespace

Listener listen_loopback() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) fail("socket");
    sockaddr_in addr = loopback(0);  // port 0: let the kernel pick a free port
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) fail("bind", fd);
    if (::listen(fd, 16) < 0) fail("listen", fd);
    socklen_t len = sizeof addr;
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) < 0) fail("getsockname", fd);
    return {fd, ntohs(addr.sin_port)};
}

int accept_one(int listen_fd) {
    const int fd = ::accept(listen_fd, nullptr, nullptr);
    if (fd < 0) fail("accept");
    return fd;
}

int connect_loopback(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) fail("socket");
    const sockaddr_in addr = loopback(port);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) < 0) fail("connect", fd);
    return fd;
}

std::string check_ready(int fd) {
    tcp_info info{};
    socklen_t len = sizeof info;
    if (::getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) < 0) return "TCP_INFO unavailable";
    if (info.tcpi_state != TCP_ESTABLISHED) return "not in ESTABLISHED state";
    int unread = 0;
    if (::ioctl(fd, FIONREAD, &unread) < 0) return "FIONREAD unavailable";
    if (unread != 0) return "unread bytes already waiting";
    return {};
}

}  // namespace turtle::tcp
