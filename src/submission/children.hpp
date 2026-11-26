#pragma once
#include "submission/network.hpp"
#include "submission/control_fd.hpp"
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace turtle::submission {
inline volatile std::sig_atomic_t interrupted = 0;
inline void stop(int sig) { interrupted = sig; }
inline void check_stop() { if (interrupted) throw std::runtime_error("run interrupted"); }
inline void syscheck(bool ok, const char *what) {
  if (!ok) throw std::runtime_error(std::string(what) + ": " + std::strerror(errno));
}
class Fd {
  int n_;
public:
  explicit Fd(int n = -1) : n_(n) {}
  ~Fd() { if (n_ >= 0) close(n_); }
  Fd(Fd &&other) noexcept : n_(std::exchange(other.n_, -1)) {}
  Fd &operator=(Fd &&other) noexcept {
    if (n_ >= 0) close(n_);
    n_ = std::exchange(other.n_, -1); return *this;
  }
  int get() const { return n_; }
};
inline std::array<Fd,2> control_socket() {
  int fds[2];
  syscheck(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0, "control socketpair");
  return {Fd(fds[0]),Fd(fds[1])};
}
using Clock = std::chrono::steady_clock;
inline auto deadline() { return Clock::now() + std::chrono::seconds(65); }
inline void exec_args(const std::vector<std::string> &args) {
  std::vector<char*> argv;
  for (const auto &s : args) argv.push_back(const_cast<char*>(s.c_str()));
  argv.push_back(nullptr);
  execv(argv[0], argv.data());
  syscheck(false, "exec");
}
inline void own_parent(pid_t parent) {
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(125);
}
class RoleProcess {
  pid_t pid_ = -1;
  Fd channel_;
public:
  RoleProcess(const Network &net, bool server, const std::vector<std::string> &args,
              const std::filesystem::path &errors) {
    auto ends = control_socket();
    auto stdout_path = errors; stdout_path.replace_extension(".stdout");
    Fd output(open(stdout_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    Fd input(open("/dev/null", O_RDONLY | O_CLOEXEC));
    syscheck(output.get() >= 0 && input.get() >= 0, "role stdio");
    Fd log(open(errors.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    syscheck(log.get() >= 0, "role stderr");
    auto parent = getpid();
    pid_ = fork();
    syscheck(pid_ >= 0, "fork role");
    if (pid_ == 0) {
      try {
        own_parent(parent);
        syscheck(dup2(log.get(), STDERR_FILENO) >= 0 && dup2(input.get(), STDIN_FILENO) >= 0 &&
                 dup2(output.get(), STDOUT_FILENO) >= 0, "role log channels");
        net.enter(server);
        own_parent(parent);
        syscheck(dup2(ends[1].get(),role_control_fd) >= 0 &&
                 fcntl(role_control_fd,F_SETFD,0) == 0, "prepare role control socket");
        syscheck(close_range(role_control_fd + 1, ~0U, 0) == 0, "close inherited descriptors");
        signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL);
        exec_args(args);
      } catch (const std::exception &e) { std::fprintf(stderr, "%s\n", e.what()); }
      _exit(126);
    }
    channel_ = std::move(ends[0]);
  }
  RoleProcess(const RoleProcess &) = delete;
  ~RoleProcess() {
    if (pid_ > 0) {
      kill(pid_, SIGKILL);
      int status;
      while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
    }
  }
  pid_t pid() const { return pid_; }
  void send(std::string line) {
    line += '\n';
    ssize_t n;
    do { check_stop(); n = write(channel_.get(), line.data(), line.size()); } while (n < 0 && errno == EINTR);
    syscheck(n == static_cast<ssize_t>(line.size()), "send role command");
  }
  std::string read_line(Clock::time_point until) const {
    std::string line;
    for (;;) {
      check_stop();
      if (Clock::now() >= until) throw std::runtime_error("role_deadline_exceeded");
      pollfd p{channel_.get(), POLLIN, 0};
      int n = poll(&p, 1, 200);
      if (n == 0 || (n < 0 && errno == EINTR)) continue;
      syscheck(n >= 0, "poll role");
      char ch;
      n = read(channel_.get(), &ch, 1);
      if (n < 0 && errno == EINTR) continue;
      if (n != 1) throw std::runtime_error("role exited before reporting its result");
      if (ch == '\n') return line;
      if (line.size() >= 32) throw std::runtime_error("invalid role response");
      line += ch;
    }
  }
  void expect(const std::string &word, Clock::time_point until) const {
    if (read_line(until) != word) throw std::runtime_error("expected role response: " + word);
  }
  void finish() {
    send("QUIT");
    int status = 0;
    auto until = Clock::now() + std::chrono::seconds(3);
    for (;;) {
      check_stop();
      auto n = waitpid(pid_, &status, WNOHANG);
      if (n == pid_) { pid_ = -1; break; }
      if (n < 0 && errno != EINTR) syscheck(false, "wait for role");
      if (Clock::now() >= until) throw std::runtime_error("role did not stop");
      usleep(2000);
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status)) throw std::runtime_error("role did not exit cleanly");
  }
};
} // namespace turtle::submission
