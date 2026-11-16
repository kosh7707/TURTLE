#pragma once
#include "observation/observation.hpp"
#include <cstdint>
#include <span>
#include <string>
namespace turtle {
class Socket {
    int fd_ = -1;

  public:
    explicit Socket(int fd = -1) : fd_(fd) {}
    ~Socket();
    Socket(Socket&&) noexcept;
    Socket& operator=(Socket&&) noexcept;
    Socket(const Socket&) = delete;
    int fd() const {
        return fd_;
    }
};
Socket listen_socket(const std::string&, std::uint16_t);
Socket accept_socket(const Socket&, std::uint64_t deadline);
Socket connect_socket(const std::string&, std::uint16_t, std::uint64_t deadline);
void wait_socket(int, bool outgoing, std::uint64_t deadline, Observer* = nullptr,
                 std::uint64_t connection = 0);
void write_all(int, std::span<const std::uint8_t>, std::uint64_t deadline);
void read_all(int, std::span<std::uint8_t>, std::uint64_t deadline);
} // namespace turtle
