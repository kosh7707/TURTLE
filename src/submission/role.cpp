#include "submission/endpoints.hpp"
#include "submission/control_fd.hpp"
#include "submission/process_maps.hpp"
#include "submission/role_measure.hpp"

#include <turtle/implementation.hpp>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <linux/tcp.h>
#include <sys/ioctl.h>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace {
namespace fs = std::filesystem;
using std::string_view;
using turtle::submission::Interval;
using turtle::submission::TransportTrace;
constexpr bool server = TURTLE_SUBMISSION_SERVER == 1;
constexpr const char *role = server ? "server" : "client";
constexpr string_view cad = "ping", sad1 = "hello", sad2 = "pong";

struct Outcome {
  const char *status = "passed";
  const char *reason = "";
};

void require(bool ok, const char *what) {
  if (!ok)
    throw std::runtime_error(what);
}

bool timed_out(int code) {
  return code == EAGAIN || code == EWOULDBLOCK || code == ETIMEDOUT ||
         code == EINPROGRESS;
}

[[noreturn]] void io_failure(const char *operation) {
  throw Outcome{timed_out(errno) ? "timeout" : "failed", operation};
}

class Socket {
  int fd_ = -1;

public:
  explicit Socket(int fd) : fd_(fd) {
    if (fd_ < 0)
      io_failure("tcp_socket");
  }
  ~Socket() {
    if (fd_ >= 0)
      close(fd_);
  }
  Socket(const Socket &) = delete;
  Socket(Socket &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  int get() const { return fd_; }
};

sockaddr_in address(const char *host, string_view port) {
  sockaddr_in a{};
  unsigned number = 0;
  const auto end = port.data() + port.size();
  const auto parsed = std::from_chars(port.data(), end, number);
  require(parsed.ec == std::errc{} && parsed.ptr == end && number &&
              number <= 65535,
          "invalid port");
  a.sin_family = AF_INET;
  a.sin_port = htons(static_cast<unsigned short>(number));
  require(inet_pton(AF_INET, host, &a.sin_addr) == 1, "invalid IPv4 address");
  return a;
}

void set_timeouts(int fd) {
  const timeval timeout{30, 0};
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) != 0 ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) != 0)
    io_failure("tcp_set_timeout");
}

Socket listener(const sockaddr_in &a) {
  Socket fd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  int enabled = 1;
  if (setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof enabled) != 0)
    io_failure("tcp_set_reuseaddr");
  set_timeouts(fd.get());
  if (bind(fd.get(), reinterpret_cast<const sockaddr *>(&a), sizeof a) != 0 ||
      listen(fd.get(), 1) != 0)
    io_failure("tcp_listen");
  return fd;
}

Socket connect_socket(const sockaddr_in &a, int listening_fd) {
  if constexpr (server) {
    int fd;
    do {
      fd = accept4(listening_fd, nullptr, nullptr, SOCK_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
      io_failure("tcp_accept");
    return Socket(fd);
  } else {
    Socket fd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    set_timeouts(fd.get());
    if (connect(fd.get(), reinterpret_cast<const sockaddr *>(&a), sizeof a) != 0)
      io_failure("tcp_connect");
    return fd;
  }
}

int configure_tcp(int fd, int requested) {
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &requested,
                 sizeof requested) != 0)
    io_failure("tcp_set_nodelay");
  int effective = -1;
  socklen_t length = sizeof effective;
  if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &effective, &length) != 0 ||
      length != sizeof effective || effective != requested)
    throw Outcome{"failed", "tcp_verify_nodelay"};
  return effective;
}

// TCP preparation is outside the timer. A bridge must not use the connected
// descriptor to move TLS work into setup or hook installation. Inspect both
// roles before either is allowed to enter its first timed TLS operation.
void check_unused_transport(int fd) {
  tcp_info info{};
  socklen_t size = sizeof info;
  int pending = -1;
  if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &size) != 0 ||
      size < offsetof(tcp_info, tcpi_data_segs_out) + sizeof info.tcpi_data_segs_out ||
      ioctl(fd, TIOCOUTQ, &pending) != 0)
    throw Outcome{"unavailable", "cannot_verify_clean_transport"};
  if (info.tcpi_data_segs_in || info.tcpi_data_segs_out || info.tcpi_bytes_received || pending)
    throw Outcome{"failed", "payload_before_first_tls_call"};
}

unsigned socket_port(int fd, bool local) {
  sockaddr_in a{};
  socklen_t length = sizeof a;
  auto query = local ? getsockname : getpeername;
  if (query(fd, reinterpret_cast<sockaddr *>(&a), &length) != 0 ||
      length != sizeof a || a.sin_family != AF_INET)
    throw Outcome{"failed", "tcp_endpoint"};
  return ntohs(a.sin_port);
}

void response(std::string line) {
  line += '\n';
  ssize_t n;
  do {
    n = send(turtle::submission::role_control_fd, line.data(), line.size(), MSG_NOSIGNAL);
  } while (n < 0 && errno == EINTR);
  require(n == static_cast<ssize_t>(line.size()), "controller output closed");
}

std::string command() {
  std::string line;
  for (;;) {
    char c;
    const auto n = read(turtle::submission::role_control_fd, &c, 1);
    if (n < 0 && errno == EINTR) continue;
    if (n == 0 && line.empty()) return "QUIT";
    require(n == 1 && line.size() < 80, "invalid controller command");
    if (c == '\n') return line;
    line += c;
  }
}

void check(turtle_status status) {
  if (status == TURTLE_TLS_UNSUPPORTED)
    throw Outcome{"unsupported", "tls_operation_unsupported"};
  if (status != TURTLE_TLS_OK)
    io_failure("tls_handshake");
}

class AppLog {
  struct Row {
    const char *event;
    const char *message;
    std::array<char, sad1.size()> data{};
    size_t size;
  };

  std::array<Row, 64> rows_{};
  size_t count_ = 0;

public:
  bool add(const char *event, const char *message, string_view bytes) noexcept {
    if (count_ == rows_.size() || bytes.size() > rows_[0].data.size())
      return false;
    auto &row = rows_[count_++];
    row.event = event;
    row.message = message;
    row.size = bytes.size();
    if (row.size)
      std::memcpy(row.data.data(), bytes.data(), row.size);
    return true;
  }

  void write(std::ostream &out) const {
    constexpr char hex[] = "0123456789abcdef";
    out << "event,message,bytes,hex\n";
    for (size_t i = 0; i < count_; ++i) {
      const auto &row = rows_[i];
      out << row.event << ',' << row.message << ',' << row.size << ',';
      for (size_t j = 0; j < row.size; ++j) {
        const auto byte = static_cast<unsigned char>(row.data[j]);
        out << hex[byte >> 4] << hex[byte & 15];
      }
      out << '\n';
    }
  }
};

class Trial {
  const char scenario_;
  const bool mutual_;
  bool started_ = false, accepting_greeting_ = false;
  bool app_log_complete_ = true, invalid_report_ = false;
  size_t greeting_accepted_ = 0;
  Interval interval_;
  AppLog app_;
  std::optional<turtle_session_info> session_;

  void log(const char *event, const char *message = "", string_view data = {}) {
    app_log_complete_ &= app_.add(event, message, data);
  }

  void begin() noexcept {
    if (!started_) {
      started_ = true;
      interval_.start();
    }
  }

  void validate_session() const {
    if (invalid_report_)
      throw Outcome{"failed", "invalid_session_report"};
    if (!session_)
      return;
    const auto &s = *session_;
    if (s.tls13 == 0 || s.resumed == 1 || s.early_data == 1 ||
        ((!server || mutual_) &&
         (s.peer_cert_present == 0 || s.peer_verified == 0)))
      throw Outcome{"failed", "session_policy"};
  }

  void handshake(turtle_tls *tls, bool greet = false) {
    accepting_greeting_ = greet;
    errno = 0;
    begin();
    const auto rc = server
        ? turtle_tls_accept(tls, greet ? reinterpret_cast<const unsigned char *>(sad1.data()) :
                                        nullptr, greet ? sad1.size() : 0)
        : turtle_tls_connect(tls);
    if (scenario_ == '0' && rc == TURTLE_TLS_OK)
      interval_.stop();
    check(rc);
    accepting_greeting_ = false;
    if (invalid_report_ || (greeting_accepted_ && greeting_accepted_ != sad1.size()))
      throw Outcome{"failed", "invalid_bridge_report"};
    validate_session();
    log("handshake_complete");
  }

  void send(turtle_tls *tls, string_view left, const char *message,
            bool primary_end) {
    while (!left.empty()) {
      log("write_attempt", message, left);
      errno = 0;
      const auto n = turtle_app_send(tls,
                                    reinterpret_cast<const unsigned char *>(left.data()),
                                    left.size());
      if (n > 0 && static_cast<size_t>(n) == left.size() && primary_end)
        interval_.stop();
      if (n <= 0)
        io_failure("tls_app_write");
      if (static_cast<size_t>(n) > left.size())
        throw Outcome{"failed", "invalid_write_length"};
      log("write_accepted", message, left.substr(0, n));
      left.remove_prefix(n);
    }
  }

  void receive(turtle_tls *tls, string_view first, const char *message,
               string_view second = {}) {
    std::array<char, sad1.size() + sad2.size()> bytes{};
    const size_t total = first.size() + second.size();
    size_t have = 0;
    while (have != total) {
      errno = 0;
      begin();
      const auto n = turtle_app_recv(tls,
                                    reinterpret_cast<unsigned char *>(bytes.data() + have),
                                    total - have);
      if (n < 0)
        io_failure("tls_app_read");
      if (n == 0)
        throw Outcome{"failed", "app_unexpected_eof"};
      if (static_cast<size_t>(n) > total - have)
        throw Outcome{"failed", "invalid_read_length"};
      const auto next = have + static_cast<size_t>(n);
      if ((!server && scenario_ == '2' && next == total) ||
          (!server && scenario_ == '3' && have == 0) ||
          (!server && scenario_ == '4' && have <= first.size() &&
           next > first.size()))
        interval_.stop();
      const string_view received(bytes.data(), next);
      if (have < first.size()) {
        log("read_return", message,
            received.substr(have, std::min(next, first.size()) - have));
        if (next >= first.size()) {
          auto actual = received.substr(0, first.size());
          if (actual != first)
            throw Outcome{"failed", "app_payload_mismatch"};
          if (server && scenario_ == '1')
            interval_.stop();
          log("validated", message, actual);
        }
      }
      if (next > first.size()) {
        const auto offset = std::max(have, first.size());
        log("read_return", "SAD2", received.substr(offset, next - offset));
        if (next == total) {
          auto actual = received.substr(first.size());
          if (actual != second)
            throw Outcome{"failed", "app_payload_mismatch"};
          log("validated", "SAD2", actual);
        }
      }
      have = next;
    }
  }

public:
  Trial(char scenario, bool mutual, bool measured)
      : scenario_(scenario), mutual_(mutual),
        interval_(measured, turtle::submission::end_event(scenario, server),
                  !server || scenario != '2') {}

  static void report_session(void *context, const turtle_session_info *info) noexcept {
    auto &t = *static_cast<Trial *>(context);
    if (!t.started_ || !info || t.session_) {
      t.invalid_report_ = true;
      return;
    }
    for (const int value : {info->tls13, info->resumed, info->early_data,
                            info->peer_cert_present, info->peer_verified})
      if (value < -1 || value > 1) {
        t.invalid_report_ = true;
        return;
      }
    t.session_ = *info;
  }

  static void greeting_written(void *context, const unsigned char *bytes,
                               size_t size) noexcept {
    auto &t = *static_cast<Trial *>(context);
    if (!t.accepting_greeting_ || !bytes || !size ||
        size > sad1.size() - t.greeting_accepted_) {
      t.invalid_report_ = true;
      return;
    }
    const string_view accepted(reinterpret_cast<const char *>(bytes), size);
    if (accepted != sad1.substr(t.greeting_accepted_, size)) {
      t.invalid_report_ = true;
      return;
    }
    t.greeting_accepted_ += size;
    t.log("write_accepted", "SAD1", accepted);
  }

  void run(turtle_tls *tls) {
    const bool request = scenario_ == '1' || scenario_ == '3' || scenario_ == '4';
    const bool greeting = scenario_ == '2' || scenario_ == '4';
    const bool reply = scenario_ == '3' || scenario_ == '4';
    if (!server && scenario_ == '2')
      receive(tls, sad1, "SAD1");
    handshake(tls, server && greeting);
    if constexpr (server) {
      if (request)
        receive(tls, cad, "CAD");
      if (reply)
        send(tls, sad2, "SAD2", true);
    } else {
      if (request)
        send(tls, cad, "CAD", scenario_ == '1');
      if (reply) {
        if (greeting)
          receive(tls, sad1, "SAD1", sad2);
        else
          receive(tls, sad2, "SAD2");
      }
    }
    if (!app_log_complete_)
      throw Outcome{"failed", "app_log_overflow"};
  }

  void write_app(std::ostream &out) const { app_.write(out); }

  void write_timing(std::ostream &out) const { interval_.write(out); }

  void write_session(std::ostream &out) const {
    const auto s = session_.value_or(turtle_session_info{-1, -1, -1, -1, -1});
    for (const auto value : {s.tls13, s.resumed, s.early_data,
                             s.peer_cert_present, s.peer_verified}) {
      if (value >= 0)
        out << value;
      out << ',';
    }
    if (greeting_accepted_ == sad1.size() && !invalid_report_)
      out << 1;
  }
};

template <typename Writer>
void publish(const fs::path &path, const Writer &write) {
  const auto tmp = fs::path(path.string() + ".partial");
  std::ofstream out(tmp);
  write(out);
  out.close();
  require(bool(out), "write evidence");
  fs::rename(tmp, path);
}

struct Role {
  sockaddr_in target;
  fs::path output;
  bool measured;
  char scenario;
  bool mutual;
  std::string ca, cert, key;
  int nodelay;
  std::optional<Socket> listening;

  bool attempt(const std::string &id) {
    const auto path = (output / (id + "." + role)).string();
    auto trace = measured ? std::make_unique<TransportTrace>() : nullptr;
    Trial trial(scenario, mutual, measured);
    const turtle_tls_config cfg{server ? TURTLE_SERVER : TURTLE_CLIENT,
                                mutual ? TURTLE_MUTUAL_AUTH : TURTLE_SERVER_AUTH,
                                ca.c_str(), cert.empty() ? nullptr : cert.c_str(),
                                key.empty() ? nullptr : key.c_str(),
                                server ? (mutual ? "client.turtle.test" : nullptr)
                                       : "localhost",
                                &trial, Trial::report_session,
                                server ? Trial::greeting_written : nullptr};
    int effective = -1;
    unsigned local = 0, remote = 0;
    bool keep_running = true;
    Outcome result;
    try {
      auto fd = connect_socket(target, listening ? listening->get() : -1);
      set_timeouts(fd.get());
      effective = configure_tcp(fd.get(), nodelay);
      local = socket_port(fd.get(), true);
      remote = socket_port(fd.get(), false);
      errno = 0;
      std::unique_ptr<turtle_tls, decltype(&turtle_tls_free)> tls(
          turtle_tls_setup(&cfg, fd.get()), turtle_tls_free);
      if (!tls)
        io_failure("tls_setup");

      const auto hooks = trace ? trace->hooks() : turtle_transport_hooks{};
      if (trace) {
        const auto bound = turtle_tls_set_hooks(tls.get(), &hooks);
        if (bound != TURTLE_TLS_OK)
          throw Outcome{bound == TURTLE_TLS_UNSUPPORTED ? "unsupported" : "failed",
                        "transport_hook_install"};
      }
      check_unused_transport(fd.get());
      response("ARMED");
      const auto go = command();
      try {
        if (go == "GO")
          trial.run(tls.get());
        else if (go == "ABORT" || go == "QUIT") {
          keep_running = go != "QUIT";
          result = {"aborted", "controller_abort"};
        } else
          throw Outcome{"failed", "controller_command"};
      } catch (const Outcome &e) {
        result = e;
      }
      if (trace)
        trace->detached(turtle_tls_set_hooks(tls.get(), nullptr) == TURTLE_TLS_OK);
      // Close the data path before publishing evidence, including on errors.
      shutdown(fd.get(), SHUT_RDWR);
      try {
        publish(path + ".maps", [&](std::ostream &out) {
          std::ifstream in("/proc/self/maps");
          require(turtle::submission::write_process_maps(in, out), "process maps");
        });
      } catch (const std::exception &e) {
        std::fprintf(stderr, "%s %s: maps: %s\n", role, id.c_str(), e.what());
      }
    } catch (const Outcome &e) {
      result = e;
    }
    if (result.status != string_view("passed"))
      std::fprintf(stderr, "%s %s: %s (%s)\n", role, id.c_str(), result.status,
                   result.reason);
    try {
      publish(path + ".app.csv", [&](std::ostream &out) { trial.write_app(out); });
      if (trace)
        publish(path + ".transport.csv",
                [&](std::ostream &out) { trace->write(out); });
      // Publish the row last: its presence does not mask an incomplete artifact.
      publish(path + ".csv", [&](std::ostream &out) {
        out << "status,reason,pid,tcp_nodelay,local_port,remote_port,wall_ns,wall_status,start_ns,"
               "end_ns,end_event,cycles,pmu_status,pmu_reason,pmu_enabled_ns,pmu_running_ns,"
               "tls13,resumed,early_data,peer_cert_present,peer_verified,server_first,transport_status\n";
        out << result.status << ',' << result.reason << ',' << getpid() << ',';
        if (effective >= 0)
          out << effective;
        out << ',';
        if (local)
          out << local;
        out << ',';
        if (remote)
          out << remote;
        out << ',';
        trial.write_timing(out);
        out << ',';
        trial.write_session(out);
        out << ',' << (trace ? trace->complete() ? "complete" : "incomplete"
                             : "not_collected") << '\n';
      });
    } catch (const std::exception &e) {
      std::fprintf(stderr, "%s %s: evidence: %s\n", role, id.c_str(), e.what());
    }
    response("DONE");
    return keep_running;
  }
};

int run(int argc, char **argv) {
  require(fcntl(turtle::submission::role_control_fd, F_SETFD, FD_CLOEXEC) == 0, "missing controller channel");
  require(argc == 8, "expected HOST PORT CASE_DIR measured|peer SCENARIO AUTH CREDENTIAL_DIR");
  const auto *setting = std::getenv("TURTLE_TCP_NODELAY");
  const string_view policy = setting ? setting : "on";
  require(policy == "on" || policy == "off", "invalid TCP_NODELAY setting");
  const string_view mode = argv[4], scenario = argv[5], auth = argv[6];
  require(mode == "measured" || mode == "peer", "invalid measurement mode");
  require(scenario.size() == 2 && scenario.front() == 'S' &&
              scenario.back() >= '0' && scenario.back() <= '4',
          "invalid scenario");
  require(auth == "server" || auth == "mtls", "invalid authentication mode");
  require(std::signal(SIGPIPE, SIG_IGN) != SIG_ERR, "signal setup");
  const fs::path credentials(argv[7]);
  const auto leaf = [&](const char *suffix) {
    return (credentials / (std::string(role) + suffix)).string();
  };
  const bool mutual = auth == "mtls";
  Role runner{address(argv[1], argv[2]), argv[3], mode == "measured", scenario.back(),
              mutual, (credentials / "ca.crt").string(),
              server || mutual ? leaf(".crt") : "", server || mutual ? leaf(".key") : "",
              policy == "on", std::nullopt};
  require(fs::is_directory(runner.output), "invalid evidence directory");
  if constexpr (server)
    runner.listening.emplace(listener(runner.target));
  response("READY");
  for (auto line = command(); line != "QUIT"; line = command()) {
    const auto id = string_view(line).substr(std::min<size_t>(4, line.size()));
    require(line.starts_with("RUN ") && !id.empty() && id.size() <= 64 &&
                id.find_first_not_of("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-") ==
                    string_view::npos,
            "invalid RUN command");
    if (!runner.attempt(std::string(id)))
      break;
  }
  return 0;
}
} // namespace

int main(int argc, char **argv) {
  try {
    return run(argc, argv);
  } catch (const Outcome &e) {
    std::fprintf(stderr, "%s: %s (%s)\n", role, e.status, e.reason);
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s: %s\n", role, e.what());
  }
  return 1;
}
