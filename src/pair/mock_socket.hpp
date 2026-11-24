#pragma once

#include "frame/detail/io_boundary.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace mock {

// These are plain fixture tokens, not TLS records.
inline constexpr std::string_view client_hello = "mock CH\n";
inline constexpr std::string_view server_flight =
    "mock SH + protected server flight\n";
inline constexpr std::string_view client_finished = "mock CF\n";

inline int checked(int result, const char *operation) {
  if (result < 0)
    throw std::system_error(errno, std::generic_category(), operation);
  return result;
}

inline sockaddr_in loopback(std::uint16_t port) {
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  return address;
}

class Socket {
public:
  explicit Socket(int fd = ::socket(AF_INET, SOCK_STREAM, 0))
      : fd_(checked(fd, "socket")) {}
  ~Socket() { ::close(fd_); }
  Socket(const Socket &) = delete;
  Socket &operator=(const Socket &) = delete;
  int fd() const { return fd_; }

  turtle_io_boundary boundary() {
    return {this, [](void *self, turtle_io_hooks hooks) {
              static_cast<Socket *>(self)->hooks_ = hooks;
            }};
  }

  void send(std::string_view bytes) {
    while (!bytes.empty()) {
      if (hooks_.before_send)
        hooks_.before_send(hooks_.context);
      auto n = ::send(fd_, bytes.data(), bytes.size(), MSG_NOSIGNAL);
      if (n < 0 && errno == EINTR)
        continue;
      if (n < 0)
        throw std::system_error(errno, std::generic_category(), "send");
      if (n == 0)
        throw std::runtime_error("send made no progress");
      bytes.remove_prefix(static_cast<std::size_t>(n));
    }
  }

  void expect(std::string_view expected) {
    std::string input(expected.size(), '\0');
    std::size_t used = 0;
    while (used < input.size()) {
      auto n = ::recv(fd_, input.data() + used, input.size() - used, 0);
      if (n < 0 && errno == EINTR)
        continue;
      if (n < 0)
        throw std::system_error(errno, std::generic_category(), "recv");
      if (n == 0)
        throw std::runtime_error("peer closed during mock flight");
      if (hooks_.after_receive)
        hooks_.after_receive(hooks_.context);
      used += static_cast<std::size_t>(n);
    }
    if (input != expected)
      throw std::runtime_error("unexpected mock flight");
  }

private:
  int fd_;
  turtle_io_hooks hooks_{};
};

} // namespace mock
