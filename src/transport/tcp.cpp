#include "transport/tcp.hpp"
#include <fcntl.h>

#include <arpa/inet.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <system_error>

namespace turtle::tcp {
namespace {

constexpr std::uint8_t tcp_established_state = 1;

[[noreturn]] void fail(const char* what, int fd = -1) {
    const int error = errno;
    if (fd >= 0)
        ::close(fd);
    throw std::system_error(error, std::generic_category(), what);
}

sockaddr_in numeric_ipv4(const std::string& address, std::uint16_t port) {
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_port = htons(port);
    const int parsed = ::inet_pton(AF_INET, address.c_str(), &result.sin_addr);
    if (parsed == 0)
        throw std::invalid_argument("IPv4 address must be numeric: " + address);
    if (parsed < 0)
        fail("inet_pton");
    return result;
}

sockaddr_in loopback(std::uint16_t port) {
    return numeric_ipv4("127.0.0.1", port);
}

Endpoint endpoint_from(const sockaddr_in& address) {
    char text[INET_ADDRSTRLEN]{};
    if (::inet_ntop(AF_INET, &address.sin_addr, text, sizeof(text)) == nullptr)
        fail("inet_ntop");
    return {text, ntohs(address.sin_port)};
}

Endpoint socket_endpoint(int fd, bool peer) {
    sockaddr_in address{};
    socklen_t length = sizeof(address);
    const int result = peer ? ::getpeername(fd, reinterpret_cast<sockaddr*>(&address), &length)
                            : ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length);
    if (result < 0)
        fail(peer ? "getpeername" : "getsockname");
    if (length < sizeof(address) || address.sin_family != AF_INET)
        throw std::runtime_error("socket endpoint is not IPv4");
    return endpoint_from(address);
}

template <class T> bool field_returned(socklen_t length, std::size_t offset) noexcept {
    return static_cast<std::size_t>(length) >= offset + sizeof(T);
}

} // namespace

Listener listen_loopback() {
    return listen_ipv4("127.0.0.1", 0);
}

Listener listen_ipv4(const std::string& address, std::uint16_t port) {
    const sockaddr_in bind_address = numeric_ipv4(address, port);
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        fail("socket");
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&bind_address), sizeof(bind_address)) < 0)
        fail("bind", fd);
    if (::listen(fd, 16) < 0)
        fail("listen", fd);
    try {
        const Endpoint actual = local_endpoint(fd);
        return {fd, actual.port};
    } catch (...) {
        ::close(fd);
        throw;
    }
}

int accept_one(int listen_fd) {
    const int fd = ::accept(listen_fd, nullptr, nullptr);
    if (fd < 0)
        fail("accept");
    return fd;
}

int connect_loopback(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        fail("socket");
    const sockaddr_in address = loopback(port);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0)
        fail("connect", fd);
    return fd;
}

int connect_ipv4(const std::string& source_address, const Endpoint& destination) {
    const sockaddr_in source = numeric_ipv4(source_address, 0);
    const sockaddr_in target = numeric_ipv4(destination.address, destination.port);
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        fail("socket");
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&source), sizeof(source)) < 0)
        fail("bind source", fd);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&target), sizeof(target)) < 0)
        fail("connect", fd);
    return fd;
}

Endpoint local_endpoint(int fd) {
    return socket_endpoint(fd, false);
}

DialAddress prepare_dial(const std::string& source, const Endpoint& target) {
    return {numeric_ipv4(source, 0).sin_addr.s_addr,
            numeric_ipv4(target.address, target.port).sin_addr.s_addr, htons(target.port)};
}

int begin_connect(const DialAddress& address) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        fail("socket");
    sockaddr_in source{}, target{};
    source.sin_family = target.sin_family = AF_INET;
    source.sin_addr.s_addr = address.source;
    target.sin_addr.s_addr = address.target;
    target.sin_port = address.port;
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&source), sizeof(source)) < 0)
        fail("bind source", fd);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&target), sizeof(target)) < 0 &&
        errno != EINPROGRESS)
        fail("connect", fd);
    return fd;
}

void finish_connect(int fd) {
    int error = 0;
    socklen_t size = sizeof(error);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0)
        fail("connect SO_ERROR");
    if (error) {
        errno = error;
        fail("connect completion");
    }
}

void nonblocking_listener(int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        fail("nonblocking listener");
}

int try_accept(int listener) {
    const int fd = ::accept4(listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        fail("accept");
    return fd;
}

Endpoint peer_endpoint(int fd) {
    return socket_endpoint(fd, true);
}

std::string check_ready(int fd) {
    tcp_info info{};
    socklen_t len = sizeof(info);
    if (::getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) < 0)
        return "TCP_INFO unavailable";
    if (!field_returned<decltype(info.tcpi_state)>(len, offsetof(tcp_info, tcpi_state)))
        return "TCP_INFO state unavailable";
    if (info.tcpi_state != tcp_established_state)
        return "not in ESTABLISHED state";
    int unread = 0;
    if (::ioctl(fd, FIONREAD, &unread) < 0)
        return "FIONREAD unavailable";
    if (unread != 0)
        return "unread bytes already waiting";
    return {};
}

model::TcpInfoSnapshot read_tcp_info(int fd) noexcept {
    model::TcpInfoSnapshot snapshot;
    tcp_info info{};
    socklen_t length = sizeof(info);
    if (::getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) < 0) {
        const int error = errno;
        snapshot.note = "TCP_INFO unavailable: ";
        snapshot.note += std::strerror(error);
        return snapshot;
    }
    snapshot.structure_bytes = length;
    bool missing = false;
#define TURTLE_TCP_INFO_FIELD(target, source)                                                      \
    do {                                                                                           \
        if (field_returned<decltype(info.source)>(length, offsetof(tcp_info, source)))             \
            snapshot.target = info.source;                                                         \
        else                                                                                       \
            missing = true;                                                                        \
    } while (false)
    TURTLE_TCP_INFO_FIELD(state, tcpi_state);
    TURTLE_TCP_INFO_FIELD(retransmits, tcpi_retransmits);
    TURTLE_TCP_INFO_FIELD(retrans, tcpi_retrans);
    TURTLE_TCP_INFO_FIELD(total_retrans, tcpi_total_retrans);
    TURTLE_TCP_INFO_FIELD(unacked, tcpi_unacked);
    TURTLE_TCP_INFO_FIELD(lost, tcpi_lost);
    TURTLE_TCP_INFO_FIELD(snd_mss, tcpi_snd_mss);
    TURTLE_TCP_INFO_FIELD(rcv_mss, tcpi_rcv_mss);
    TURTLE_TCP_INFO_FIELD(snd_cwnd, tcpi_snd_cwnd);
    TURTLE_TCP_INFO_FIELD(snd_ssthresh, tcpi_snd_ssthresh);
    TURTLE_TCP_INFO_FIELD(segs_out, tcpi_segs_out);
    TURTLE_TCP_INFO_FIELD(segs_in, tcpi_segs_in);
    TURTLE_TCP_INFO_FIELD(data_segs_out, tcpi_data_segs_out);
    TURTLE_TCP_INFO_FIELD(data_segs_in, tcpi_data_segs_in);
    TURTLE_TCP_INFO_FIELD(bytes_acked, tcpi_bytes_acked);
    TURTLE_TCP_INFO_FIELD(bytes_received, tcpi_bytes_received);
#undef TURTLE_TCP_INFO_FIELD
    if (missing)
        snapshot.note = "Some TCP_INFO fields are unavailable at the returned structure length";
    return snapshot;
}

} // namespace turtle::tcp
