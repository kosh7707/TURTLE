#include "net/transport.hpp"
#include <cerrno>
#include <stdexcept>
#include <utility>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
namespace turtle::net {
namespace {
void require(bool success, const char* reason) { if (!success) throw std::runtime_error(reason); }
sockaddr_in address(const char* host, std::uint16_t port) {
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_port = htons(port);
    require(::inet_pton(AF_INET, host, &result.sin_addr) == 1, "ipv4_address");
    return result;
}
std::ptrdiff_t receive(void* state, void* out, std::size_t size) {
    const auto n = ::recv(static_cast<Socket*>(state)->get(), out, size, 0);
    return n < 0 && errno == EINTR ? -2 : n;
}
std::ptrdiff_t send(void* state, const void* in, std::size_t size) {
    const auto n = ::send(static_cast<Socket*>(state)->get(), in, size, MSG_NOSIGNAL);
    return n < 0 && errno == EINTR ? -2 : n;
}
}
Socket::~Socket() { if (descriptor_ >= 0) ::close(descriptor_); }
Socket::Socket(Socket&& other) noexcept : descriptor_(std::exchange(other.descriptor_, -1)) {}
Socket listen(const char* host, std::uint16_t number) {
    Socket result(::socket(AF_INET, SOCK_STREAM, 0));
    const auto local = address(host, number);
    require(result.get() >= 0 &&
            ::bind(result.get(), reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == 0 &&
            ::listen(result.get(), 1) == 0, "listen_failed");
    return result;
}
std::uint16_t port(const Socket& listener) {
    sockaddr_in local{};
    socklen_t length = sizeof(local);
    require(::getsockname(listener.get(), reinterpret_cast<sockaddr*>(&local), &length) == 0, "getsockname_failed");
    return ntohs(local.sin_port);
}
Socket accept(const Socket& listener) {
    int descriptor;
    do { descriptor = ::accept(listener.get(), nullptr, nullptr); } while (descriptor < 0 && errno == EINTR);
    require(descriptor >= 0, "accept_failed");
    return Socket(descriptor);
}
Socket connect(const char* host, std::uint16_t number) {
    Socket result(::socket(AF_INET, SOCK_STREAM, 0));
    const auto remote = address(host, number);
    require(result.get() >= 0 &&
            ::connect(result.get(), reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) == 0, "connect_failed");
    return result;
}
Connection::Connection(Socket socket, measure::Recorder& recorder, std::size_t chunk, unsigned seconds)
    : socket_(std::move(socket)), framer_({&socket_, receive, send}, recorder, chunk) {
    const timeval timeout{static_cast<time_t>(seconds), 0};
    const int one = 1;
    require(::setsockopt(socket_.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
            ::setsockopt(socket_.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0 &&
            ::setsockopt(socket_.get(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0, "socket_options_failed");
}
}
