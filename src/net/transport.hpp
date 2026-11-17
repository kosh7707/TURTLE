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
    Connection(Socket socket, measure::Recorder&, std::size_t chunk, unsigned timeout);
    turtle_transport transport() noexcept { return framer_.transport(); }
    bool at_record_boundary() const noexcept { return framer_.at_record_boundary(); }
private:
    Socket socket_;
    frame::Framer framer_;
};
}
