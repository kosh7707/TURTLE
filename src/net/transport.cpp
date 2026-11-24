#include "net/transport.hpp"
#include <cerrno>
#include <stdexcept>
#include <utility>
#include <chrono>
#include <thread>
#include <poll.h>
#include <sys/ioctl.h>
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
    const auto n = ::recv(static_cast<Socket*>(state)->get(), out, size, MSG_DONTWAIT);
    if (n < 0 && errno == EINTR) return frame::interrupted;
    return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? static_cast<ptrdiff_t>(TURTLE_WANT_READ) : n;
}
std::ptrdiff_t send(void* state, const void* in, std::size_t size) {
    const auto n = ::send(static_cast<Socket*>(state)->get(), in, size, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n < 0 && errno == EINTR) return frame::interrupted;
    return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? static_cast<ptrdiff_t>(TURTLE_WANT_WRITE) : n;
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
Connection::Connection(Socket socket, measure::Recorder& recorder, std::size_t chunk, unsigned seconds, bool probe)
    : socket_(std::move(socket)), stream_({&socket_, receive, send}, recorder, chunk, probe), timeout_(seconds) {
    const timeval timeout{static_cast<time_t>(seconds), 0};
    const int one = 1;
    require(::setsockopt(socket_.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
            ::setsockopt(socket_.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0 &&
            ::setsockopt(socket_.get(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0, "socket_options_failed");
}
bool Connection::readable() const noexcept {
    pollfd fd{socket_.get(), POLLIN, 0};
    return ::poll(&fd,1,0)>0 && (fd.revents&(POLLIN|POLLHUP|POLLERR));
}
void Connection::wait(bool writing) const {
    pollfd fd{socket_.get(), static_cast<short>(writing ? POLLOUT : POLLIN), 0};
    int ready;
    do { ready = ::poll(&fd, 1, static_cast<int>(timeout_ * 1000)); } while (ready < 0 && errno == EINTR);
    require(ready > 0 && !(fd.revents & POLLNVAL), ready == 0 ? "socket_wait_timeout" : "socket_wait_failed");
}
int Connection::wait_either(bool first_writing, bool second_writing) const {
    const short a = first_writing ? POLLOUT : POLLIN, b = second_writing ? POLLOUT : POLLIN;
    pollfd fd{socket_.get(), static_cast<short>(a | b), 0};
    int n; do { n=::poll(&fd,1,static_cast<int>(timeout_*1000)); } while (n<0 && errno==EINTR);
    require(n>0 && !(fd.revents&POLLNVAL), n==0?"socket_wait_timeout":"socket_wait_failed");
    return (fd.revents&(POLLHUP|POLLERR)) ? 3 : ((fd.revents&a)?1:0)|((fd.revents&b)?2:0);
}
std::uint64_t Connection::queued(std::uint64_t expected) const {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_);
    do {
        int bytes = 0;
        require(ioctl(socket_.get(), FIONREAD, &bytes) == 0 && bytes >= 0, "probe_queue_unavailable");
        if (static_cast<std::uint64_t>(bytes) >= expected) return bytes;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while (std::chrono::steady_clock::now() < deadline);
    throw std::runtime_error("probe_presend_not_delivered");
}
}
