// Linked only into the stress-test OpenSSL client. Constrain this client's
// kernel buffers before the TCP handshake, never a host-wide setting.
#include <cerrno>
#include <cstdio>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
extern "C" int __real_socket(int, int, int);
extern "C" int __wrap_socket(int domain, int type, int proto) {
  int fd = __real_socket(domain, type, proto);
  if (fd < 0 || domain != AF_INET ||
      (type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) != SOCK_STREAM)
    return fd;
  int request = 1024, window = 2048;
  auto fail = [&] {
    const int e = errno;
    close(fd);
    errno = e;
    return -1;
  };
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &request, sizeof(request)) ||
      setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &request, sizeof(request)) ||
      setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &window, sizeof(window)))
    return fail();
  int rx = 0, tx = 0;
  socklen_t len = sizeof(int);
  if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rx, &len) ||
      getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &tx, &len))
    return fail();
  if (rx <= 0 || rx >= 16384 || tx <= 0 || tx >= 16384) {
    errno = EINVAL;
    return fail();
  }
  std::fprintf(stderr, "stress TCP socket buffers: rx=%d tx=%d\n", rx, tx);
  return fd;
}
