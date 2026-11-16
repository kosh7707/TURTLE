#include "socket.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
namespace turtle {
static void check(bool ok, const char* op) {
    if (!ok)
        throw std::runtime_error(std::string(op) + ": " + strerror(errno));
}
Socket::~Socket() {
    if (fd_ >= 0)
        close(fd_);
}
Socket::Socket(Socket&& s) noexcept : fd_(s.fd_) {
    s.fd_ = -1;
}
Socket& Socket::operator=(Socket&& s) noexcept {
    if (this != &s) {
        if (fd_ >= 0)
            close(fd_);
        fd_ = s.fd_;
        s.fd_ = -1;
    }
    return *this;
}
static sockaddr_in address(const std::string& ip, std::uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    check(inet_pton(AF_INET, ip.c_str(), &a.sin_addr) == 1, "IPv4");
    return a;
}
static Socket make_socket() {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    check(fd >= 0, "socket");
    Socket s(fd);
    int one = 1;
    check(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0, "TCP_NODELAY");
    return s;
}
Socket listen_socket(const std::string& ip, std::uint16_t port) {
    auto s = make_socket();
    int one = 1;
    setsockopt(s.fd(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    auto a = address(ip, port);
    check(bind(s.fd(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0, "bind");
    check(listen(s.fd(), 8) == 0, "listen");
    return s;
}
void wait_socket(int fd, bool outgoing, std::uint64_t deadline, Observer* o,
                 std::uint64_t connection) {
    Event e{};
    e.kind = Kind::Wait;
    e.connection = connection;
    e.outgoing = outgoing;
    if (o)
        e.begin = o->now();
    for (;;) {
        auto now = monotonic_ns();
        if (now >= deadline)
            throw std::runtime_error("socket deadline expired");
        pollfd p{fd, short(outgoing ? POLLOUT : POLLIN), 0};
        int rc =
            poll(&p, 1, int(std::min<std::uint64_t>((deadline - now + 999999) / 1000000, 1000)));
        if (rc < 0 && errno == EINTR)
            continue;
        check(rc >= 0, "poll");
        if (rc > 0)
            break;
    }
    if (o) {
        e.end = o->now();
        o->add(e);
    }
}
Socket accept_socket(const Socket& listener, std::uint64_t deadline) {
    for (;;) {
        int fd = accept4(listener.fd(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd >= 0) {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            return Socket(fd);
        }
        check(errno == EAGAIN || errno == EINTR, "accept");
        wait_socket(listener.fd(), false, deadline);
    }
}
Socket connect_socket(const std::string& ip, std::uint16_t port, std::uint64_t deadline) {
    auto s = make_socket();
    auto a = address(ip, port);
    int rc = connect(s.fd(), reinterpret_cast<sockaddr*>(&a), sizeof(a));
    if (rc < 0) {
        check(errno == EINPROGRESS, "connect");
        wait_socket(s.fd(), true, deadline);
        int error = 0;
        socklen_t n = sizeof(error);
        check(getsockopt(s.fd(), SOL_SOCKET, SO_ERROR, &error, &n) == 0, "connect result");
        if (error) {
            errno = error;
            check(false, "connect");
        }
    }
    return s;
}
void write_all(int fd, std::span<const std::uint8_t> b, std::uint64_t deadline) {
    while (!b.empty()) {
        auto n = send(fd, b.data(), b.size(), MSG_NOSIGNAL);
        if (n > 0)
            b = b.subspan(std::size_t(n));
        else if (n < 0 && (errno == EAGAIN || errno == EINTR))
            wait_socket(fd, true, deadline);
        else
            check(false, "send");
    }
}
void read_all(int fd, std::span<std::uint8_t> b, std::uint64_t deadline) {
    while (!b.empty()) {
        auto n = recv(fd, b.data(), b.size(), 0);
        if (n > 0)
            b = b.subspan(std::size_t(n));
        else if (n == 0)
            throw std::runtime_error("peer closed");
        else if (errno == EAGAIN || errno == EINTR)
            wait_socket(fd, false, deadline);
        else
            check(false, "receive");
    }
}
} // namespace turtle
