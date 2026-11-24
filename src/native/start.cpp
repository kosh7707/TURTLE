#include "native/start_packet.hpp"
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <poll.h>
#include <sys/socket.h>
#include <turtle/start.h>
extern "C" int turtle_wait_start(void) {
  const char *value = std::getenv("TURTLE_START_FD");
  if (!value || !*value)
    return 0;
  int fd = -1;
  const char *end = value + std::strlen(value);
  auto parsed = std::from_chars(value, end, fd);
  int type = 0;
  socklen_t size = sizeof(type);
  if (parsed.ec != std::errc{} || parsed.ptr != end || fd < 3 ||
      getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) ||
      type != SOCK_SEQPACKET)
    return -1;
  static std::atomic_flag used = ATOMIC_FLAG_INIT;
  if (used.test_and_set())
    return -1;
  auto report = [&](char opcode, uint64_t token = 0) {
    timespec t{};
    if (clock_gettime(CLOCK_MONOTONIC, &t))
      return false;
    auto p = turtle::native::detail::start_packet(
        opcode, uint64_t(t.tv_sec) * 1000000000ULL + t.tv_nsec, token);
    return send(fd, p.data(), p.size(), MSG_NOSIGNAL | MSG_DONTWAIT) ==
           static_cast<ssize_t>(p.size());
  };
  if (!report('R'))
    return -1;
  // The supervisor normally releases/declines promptly. Bound a stale or
  // non-supervisor fd too; no signal handlers or fd flags are changed.
  using Clock = std::chrono::steady_clock;
  auto deadline = Clock::now() + turtle::native::detail::start_wait_limit;
  while (Clock::now() < deadline) {
    pollfd descriptor{fd, POLLIN, 0};
    int ms =
        static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - Clock::now())
                             .count());
    int n = poll(&descriptor, 1, ms > 0 ? ms : 0);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return n == 0 ? 0 : -1;
    turtle::native::detail::StartPacket p{};
    auto count = recv(fd, p.data(), p.size(), MSG_DONTWAIT | MSG_TRUNC);
    if (count < 0 && (errno == EINTR || errno == EAGAIN))
      continue;
    if (count != static_cast<ssize_t>(p.size()))
      return -1;
    const auto token = turtle::native::detail::start_token(p);
    if (p[0] == 'G' && token)
      return report('A', token) ? 1 : -1;
    return p[0] == 'U' && !token ? 0 : -1;
  }
  return 0;
}
