#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
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

void record_buffered(int notice, int release, bool overflow) {
  std::array<char, 256> payload{};
  payload.fill('Q');
  errno = EAGAIN;
  for (int i = 0; i < (overflow ? 40000 : 96); ++i)
    turtle_observe_plain("write_attempt", payload.data(), payload.size());
  check(errno == EAGAIN, "recording changed errno");
  payload.fill('Z'); // The observer must own each recorded byte.
  check(write(notice, "x", 1) == 1, "report in-memory recording done");
  char confirm;
  check(read(release, &confirm, 1) == 1, "wait for reader");
}

enum class Outcome { complete, overflow, killed };

void check_buffered_outcome(const char *self, Outcome outcome) {
  int evidence[2], notice[2], release[2];
  check(pipe(evidence) == 0 && pipe(notice) == 0 && pipe(release) == 0, "create pipes");
  auto pid = fork();
  check(pid >= 0, "fork");
  if (pid == 0) {
    close(evidence[0]);
    close(notice[0]);
    close(release[1]);
    auto evidence_fd = std::to_string(evidence[1]);
    auto notice_fd = std::to_string(notice[1]);
    auto release_fd = std::to_string(release[0]);
    check(setenv("TURTLE_EVIDENCE_FD", evidence_fd.c_str(), 1) == 0,
          "buffered evidence environment");
    check(unsetenv("TURTLE_PMU") == 0, "clear PMU environment");
    execl("/proc/self/exe", self, "--buffer-child", notice_fd.c_str(),
          release_fd.c_str(),
          outcome == Outcome::overflow ? "overflow" : "small",
          static_cast<char *>(nullptr));
    _exit(127);
  }
  close(evidence[1]);
  close(notice[1]);
  close(release[0]);
  pollfd got{notice[0], POLLIN, 0};
  if (poll(&got, 1, 3000) != 1 || !(got.revents & POLLIN)) {
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
    check(false, "recording waited for an undrained evidence pipe");
  }
  char confirm;
  check(read(notice[0], &confirm, 1) == 1, "read recording notice");
  close(notice[0]);
  got = {evidence[0], POLLIN, 0};
  check(poll(&got, 1, 0) == 0, "evidence was written before record interval ended");
  if (outcome == Outcome::killed)
    check(kill(pid, SIGKILL) == 0, "interrupt the producer");
  else
    check(write(release[1], "x", 1) == 1, "release the producer");
  close(release[1]);
  std::string raw;
  std::array<char, 8192> data;
  ssize_t n;
  while ((n = read(evidence[0], data.data(), data.size())) > 0)
    raw.append(data.data(), static_cast<size_t>(n));
  close(evidence[0]);
  int status;
  check(n == 0 && waitpid(pid, &status, 0) == pid, "collect child");
  if (outcome == Outcome::killed) {
    check(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL && raw.empty(),
          "killed producer must not publish a valid evidence prefix");
    return;
  }
  check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
        "flush must not change the process result");
  const auto marker = raw.find("\"observer_loss\"");
  const auto seal = raw.find("\"observer_complete\"");
  if (outcome == Outcome::overflow) {
    check(marker != raw.npos && seal == raw.npos,
          "overflow must not emit a completion seal");
  } else {
    check(marker == raw.npos && seal != raw.npos, "missing completion seal");
    std::string hex;
    for (int i = 0; i < 256; ++i)
      hex += "51";
    size_t start = 0;
    int rows = 0;
    while ((start = raw.find(hex, start)) != raw.npos) {
      start += hex.size();
      ++rows;
    }
    check(rows == 96, "flush did not preserve all payloads and order of copying");
  }
}

void check_socket_options() {
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
} // namespace

int main(int argc, char **argv) {
  if (argc == 2 && std::strcmp(argv[1], "--buffer") == 0) {
    check_buffered_outcome(argv[0], Outcome::complete);
    check_buffered_outcome(argv[0], Outcome::overflow);
    check_buffered_outcome(argv[0], Outcome::killed);
    std::puts("observer buffers without pipe writes; complete, overflow and killed evidence are distinct");
    return 0;
  }
  if (argc == 5 && std::strcmp(argv[1], "--buffer-child") == 0) {
    record_buffered(std::atoi(argv[2]), std::atoi(argv[3]),
                    std::strcmp(argv[4], "overflow") == 0);
    return 0;
  }
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
    check(false, "exec observer fd child");
  }
  check(argc == 2 && std::strcmp(argv[1], "observe") == 0,
        "usage: observer-fd [--buffer]");
  check_socket_options();
}
