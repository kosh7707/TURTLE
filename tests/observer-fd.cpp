#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <turtle/observe.h>
#include <unistd.h>

namespace {
void check(bool ok, const char *msg) {
  if (!ok) {
    std::fprintf(stderr, "%s\n", msg);
    std::exit(1);
  }
}
template <class T> T option(int fd, int level, int name) {
  T value{};
  socklen_t n = sizeof(value);
  check(getsockopt(fd, level, name, &value, &n) == 0 && n == sizeof(value),
        "read option");
  return value;
}
} // namespace
int main(int argc, char **argv) {
  // The SDK reads its optional fd at load time; exec with a real write-only
  // evidence channel and no reader. SIGPIPE must not kill the application.
  if (argc == 1) {
    int p[2];
    check(pipe(p) == 0, "pipe");
    close(p[0]);
    char n[24];
    std::snprintf(n, sizeof(n), "%d", p[1]);
    check(setenv("TURTLE_EVIDENCE_FD", n, 1) == 0, "evidence environment");
    execl("/proc/self/exe", argv[0], "observe", static_cast<char *>(nullptr));
    return 1;
  }
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  check(fd >= 0, "open socket");
  int no_delay = 0;
  timeval receive{0, 347000}, transmit{0, 281000};
  check(
      !setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof no_delay) &&
          !setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &receive, sizeof receive) &&
          !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &transmit, sizeof transmit),
      "set socket options");
  auto rx = option<timeval>(fd, SOL_SOCKET, SO_RCVTIMEO),
       tx = option<timeval>(fd, SOL_SOCKET, SO_SNDTIMEO);
  struct stat before{}, after{};
  check(!fstat(fd, &before), "socket identity");
  int flags = fcntl(fd, F_GETFL), descriptor = fcntl(fd, F_GETFD);
  errno = EAGAIN;
  turtle_observe_coverage("socket", 1);
  auto before_call = turtle_observe_now(), after_call = turtle_observe_now();
  turtle_observe_io(before_call, after_call, "socket", 0, 1, -1, nullptr, 0);
  turtle_observe_coverage("socket", 0);
  check(errno == EAGAIN, "observer changed retry errno");
  check(!fstat(fd, &after) && before.st_dev == after.st_dev &&
            before.st_ino == after.st_ino,
        "observer closed or replaced socket");
  auto next_rx = option<timeval>(fd, SOL_SOCKET, SO_RCVTIMEO),
       next_tx = option<timeval>(fd, SOL_SOCKET, SO_SNDTIMEO);
  check(option<int>(fd, IPPROTO_TCP, TCP_NODELAY) == no_delay &&
            rx.tv_sec == next_rx.tv_sec && rx.tv_usec == next_rx.tv_usec &&
            tx.tv_sec == next_tx.tv_sec && tx.tv_usec == next_tx.tv_usec &&
            flags == fcntl(fd, F_GETFL) && descriptor == fcntl(fd, F_GETFD),
        "observer changed socket settings");
  check(close(fd) == 0, "application retained fd ownership");
  std::puts(
      "observer preserved native TCP options, fd ownership and retry errno");
}
