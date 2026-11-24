#include "process/process.hpp"
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdexcept>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
namespace turtle::process {
Deadline deadline(double seconds) {
  return std::chrono::steady_clock::now() +
         std::chrono::milliseconds(static_cast<long long>(seconds * 1000));
}
namespace {
void ready(int fd, Deadline end, int cancel) {
  while (true) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  end - std::chrono::steady_clock::now())
                  .count();
    if (ms <= 0)
      throw std::runtime_error("process_timeout");
    std::array<pollfd, 2> f{{{fd, POLLIN, 0}, {cancel, POLLIN, 0}}};
    int n = ::poll(f.data(), f.size(),
                   static_cast<int>(std::min<long long>(ms, 100)));
    if (n < 0 && errno != EINTR)
      throw std::runtime_error("poll_failed");
    if (f[1].revents)
      throw std::runtime_error("interrupted");
    if (f[0].revents || fd < 0)
      return;
  }
}
int decode(int s) { return WIFEXITED(s) ? WEXITSTATUS(s) : 128 + WTERMSIG(s); }
} // namespace
Child::Child(const Args &args, const Environment &env,
             const std::filesystem::path &err, Group group) : group_(group) {
  if (args.empty())
    throw std::runtime_error("empty_command");
  error_ = err.empty() ? std::tmpfile() : std::fopen(err.c_str(), "w+");
  int in[2]{-1, -1}, out[2]{-1, -1};
  if (!error_ || ::pipe2(in, O_CLOEXEC) || ::pipe2(out, O_CLOEXEC)) {
    for (int fd : {in[0], in[1], out[0], out[1]})
      if (fd >= 0)
        ::close(fd);
    if (error_)
      std::fclose(error_);
    throw std::runtime_error("process_descriptors_failed");
  }
  std::vector<char *> argv;
  for (const auto &a : args)
    argv.push_back(const_cast<char *>(a.c_str()));
  argv.push_back(nullptr);
  pid_ = ::fork();
  if (pid_ == 0) {
    if (group_ == Group::isolated)
      ::setsid();
    ::dup2(in[0], STDIN_FILENO);
    ::dup2(out[1], STDOUT_FILENO);
    ::dup2(::fileno(error_), STDERR_FILENO);
    for (int fd : {in[0], in[1], out[0], out[1]})
      ::close(fd);
    sigset_t empty;
    sigemptyset(&empty);
    ::sigprocmask(SIG_SETMASK, &empty, nullptr);
    for (const auto &[k, v] : env)
      ::setenv(k.c_str(), v.c_str(), 1);
    ::execvp(argv[0], argv.data());
    ::perror("exec");
    ::_exit(127);
  }
  ::close(in[0]);
  ::close(out[1]);
  input_ = in[1];
  output_ = out[0];
  if (pid_ < 0) {
    ::close(input_);
    ::close(output_);
    std::fclose(error_);
    throw std::runtime_error("fork_failed");
  }
}
Child::~Child() {
  stop();
  close_input();
  if (output_ >= 0)
    ::close(output_);
  if (error_)
    std::fclose(error_);
}
void Child::receive(Deadline end, int cancel) {
  ready(output_, end, cancel);
  std::array<char, 8192> b{};
  auto n = ::read(output_, b.data(), b.size());
  if (n > 0)
    buffered_.append(b.data(), static_cast<std::size_t>(n));
  else if (n == 0)
    eof_ = true;
  else if (errno != EINTR)
    throw std::runtime_error("process_read_failed");
}
std::string Child::line(Deadline end, int cancel) {
  while (true) {
    auto pos = buffered_.find('\n');
    if (pos != std::string::npos) {
      auto s = buffered_.substr(0, pos);
      buffered_.erase(0, pos + 1);
      return s;
    }
    if (eof_)
      throw std::runtime_error("unexpected_process_eof:" + buffered_);
    receive(end, cancel);
  }
}
std::string Child::collect(Deadline end, int cancel) {
  while (!eof_)
    receive(end, cancel);
  return std::exchange(buffered_, {});
}
void Child::send(const std::string &s) {
  std::size_t off = 0;
  while (off < s.size()) {
    auto n = ::write(input_, s.data() + off, s.size() - off);
    if (n > 0)
      off += static_cast<std::size_t>(n);
    else if (errno != EINTR)
      throw std::runtime_error("process_write_failed");
  }
}
void Child::close_input() {
  if (input_ >= 0) {
    ::close(input_);
    input_ = -1;
  }
}
int Child::wait(Deadline end, int cancel) {
  while (status_ < 0) {
    int s = 0;
    auto r = ::waitpid(pid_, &s, WNOHANG);
    if (r == pid_)
      status_ = decode(s);
    else if (r < 0 && errno != EINTR)
      throw std::runtime_error("waitpid_failed");
    else
      ready(-1, end, cancel);
  }
  return status_;
}
void Child::signal(int s) {
  if (pid_ > 0 && status_ < 0)
    ::kill(group_ == Group::isolated ? -pid_ : pid_, s);
}
int Child::stop() noexcept {
  if (pid_ > 0 && status_ < 0) {
    signal(SIGTERM);
    try {
      wait(deadline(2));
    } catch (...) {
      signal(SIGKILL);
      int s = 0;
      while (::waitpid(pid_, &s, 0) < 0 && errno == EINTR) {
      }
      status_ = decode(s);
    }
  }
  return status_;
}
std::string Child::errors() {
  std::fflush(error_);
  std::rewind(error_);
  std::string s;
  std::array<char, 8192> b{};
  while (auto n = std::fread(b.data(), 1, b.size(), error_))
    s.append(b.data(), n);
  return s;
}
artifact::Json command(const Args &args, double timeout, const Environment &env,
                       int cancel) {
  Child p(args, env);
  p.close_input();
  auto end = deadline(timeout);
  auto out = p.collect(end, cancel);
  int code = p.wait(end, cancel);
  return {{"argv", args},
          {"returncode", code},
          {"stdout", out},
          {"stderr", p.errors()}};
}
std::string executable(const std::string &name) {
  if (name.find('/') != std::string::npos)
    return std::filesystem::canonical(name).string();
  const char *inherited_path = std::getenv("PATH");
  std::string path = inherited_path ? inherited_path : "";
  std::size_t a = 0;
  do {
    auto b = path.find(':', a);
    auto p = std::filesystem::path(path.substr(a, b - a)) / name;
    if (::access(p.c_str(), X_OK) == 0)
      return std::filesystem::canonical(p).string();
    if (b == std::string::npos)
      break;
    a = b + 1;
  } while (true);
  throw std::runtime_error("executable_missing:" + name);
}
std::string digest(const std::filesystem::path &path) {
  auto r = command({"sha256sum", "--", path.string()});
  auto s = r.at("stdout").get<std::string>();
  if (r.at("returncode") != 0 || s.size() < 64)
    throw std::runtime_error("sha256_failed:" + path.string());
  return s.substr(0, 64);
}
} // namespace turtle::process
