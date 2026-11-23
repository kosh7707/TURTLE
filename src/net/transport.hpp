#pragma once
#include "frame/framer.hpp"
#include <cstdint>
namespace turtle::net {
class Socket {
public:
    explicit Socket(int descriptor = -1) noexcept : descriptor_(descriptor) {}
    ~Socket();
    Socket(Socket&&) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    int get() const noexcept { return descriptor_; }
private:
    int descriptor_;
};
Socket listen(const char* host, std::uint16_t port);
std::uint16_t port(const Socket&);
Socket accept(const Socket&);
Socket connect(const char* host, std::uint16_t port);
class Connection {
public:
    Connection(Socket socket, measure::Recorder&, std::size_t chunk, unsigned timeout, bool probe = false);
    turtle_transport transport() noexcept { return stream_.transport(); }
    void wait(bool writing) const;
    std::uint64_t queued(std::uint64_t expected) const;
    std::uint64_t submitted() const noexcept { return stream_.probe_sent(); }
private:
    Socket socket_;
    frame::Stream stream_;
    unsigned timeout_;
};
}
