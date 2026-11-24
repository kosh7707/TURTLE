#pragma once
#include "native/network.hpp"
#include "process/process.hpp"
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace turtle::native::detail {
using Clock = std::chrono::steady_clock;
inline auto ns() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             Clock::now().time_since_epoch())
      .count();
}
struct FD {
  int fd;
  explicit FD(int f = -1) : fd(f) {}
  ~FD() { reset(); }
  FD(const FD &) = delete;
  FD(FD &&o) noexcept : fd(std::exchange(o.fd, -1)) {}
  FD &operator=(FD &&o) noexcept {
    reset(std::exchange(o.fd, -1));
    return *this;
  }
  void reset(int f = -1) {
    if (fd >= 0)
      ::close(fd);
    fd = f;
  }
};
struct Pipe {
  FD r, w;
  Pipe() {
    int p[2];
    if (::pipe2(p, O_CLOEXEC))
      throw std::runtime_error("pipe_failed");
    r.reset(p[0]);
    w.reset(p[1]);
  }
};
inline void nonblock(int fd) {
  int f = fcntl(fd, F_GETFL);
  if (f < 0 || fcntl(fd, F_SETFL, f | O_NONBLOCK))
    throw std::runtime_error("fcntl_failed");
}
// All shared child descriptors are close-on-exec except stdin/stdout/stderr and
// the optional one-way evidence pipe. No child inherits another app's stdin.
class App {
public:
  FD in, out, ev, err, start;
  pid_t pid = -1;
  int status = -1;
  App(const process::Args &args, process::Environment env,
      bool hold_for_profile = false, const std::string &netns = {}) {
    Pipe i, o, e, d;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair))
      throw std::runtime_error("start_channel_failed");
    FD start_child(pair[1]);
    start.reset(pair[0]);
    int one = 1;
    if (setsockopt(start.fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof one))
      throw std::runtime_error("start_credentials_failed");
    env["TURTLE_START_FD"] = "5";
    nonblock(i.w.fd);
    nonblock(o.r.fd);
    nonblock(e.r.fd);
    nonblock(d.r.fd);
    env["TURTLE_EVIDENCE_FD"] = "3";
    std::vector<char *> av;
    for (auto &a : args)
      av.push_back(const_cast<char *>(a.c_str()));
    av.push_back(nullptr);
    pid = ::fork();
    if (pid < 0)
      throw std::runtime_error("fork_failed");
    if (pid == 0) {
      if (::setpgid(0, 0))
        ::_exit(126);
      // Duplicate sources above destination fds, including if invoked with a
      // standard descriptor closed.
      int dest = 0;
      std::array<int, 4> src{i.r.fd, o.w.fd, d.w.fd, e.w.fd};
      for (int &s : src) {
        s = fcntl(s, F_DUPFD_CLOEXEC, 6);
        if (s < 0)
          ::_exit(126);
      }
      int start_fd = fcntl(start_child.fd, F_DUPFD_CLOEXEC, 6);
      if (start_fd < 0)
        ::_exit(126);
      for (int s : src)
        if (dup2(s, dest++) < 0)
          ::_exit(126);
      ::close(4);
      if (dup2(start_fd, 5) < 0)
        ::_exit(126);
      if (::close_range(6, ~0U, 0))
        ::_exit(126);
      sigset_t mask;
      sigemptyset(&mask);
      ::sigprocmask(SIG_SETMASK, &mask, nullptr);
      ::signal(SIGPIPE, SIG_DFL);
      ::unsetenv("TURTLE_PROBE_GATE_FD");
      ::unsetenv("TURTLE_PMU");
      ::unsetenv("TURTLE_LISTEN_FD");
      for (auto &[k, v] : env)
        if (::setenv(k.c_str(), v.c_str(), 1))
          ::_exit(126);
      if (!netns.empty()) {
        FD handle(::open(netns.c_str(), O_RDONLY | O_CLOEXEC));
        if (handle.fd < 0 || ::setns(handle.fd, CLONE_NEWNET) < 0) {
          ::perror("setns");
          ::_exit(126);
        }
      }
      if (hold_for_profile)
        ::raise(SIGSTOP);
      ::execv(av[0], av.data());
      ::perror("execv");
      ::_exit(127);
    }
    ::setpgid(pid, pid);
    in = std::move(i.w);
    out = std::move(o.r);
    ev = std::move(e.r);
    err = std::move(d.r);
  }
  bool done() {
    if (status >= 0)
      return true;
    // Leave the group leader waitable until destruction; otherwise its PID
    // could be reused before a timed-out grandchild's group is cleaned up.
    siginfo_t info{};
    auto r = waitid(P_PID, pid, &info, WEXITED | WNOHANG | WNOWAIT);
    if (r < 0 && errno != EINTR)
      throw std::runtime_error("waitid_failed");
    if (info.si_pid == pid)
      status =
          info.si_code == CLD_EXITED ? info.si_status : 128 + info.si_status;
    return status >= 0;
  }
  ~App() {
    if (pid > 0) {
      ::kill(-pid, SIGKILL);
      ::kill(pid, SIGKILL);
      while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
      }
    }
  }
};
inline unsigned port() {
  FD s(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t n = sizeof(a);
  if (s.fd < 0 || bind(s.fd, reinterpret_cast<sockaddr *>(&a), n) ||
      getsockname(s.fd, reinterpret_cast<sockaddr *>(&a), &n))
    throw std::runtime_error("loopback_port_failed");
  return ntohs(a.sin_port);
}
} // namespace turtle::native::detail
