#include "native/submission_endpoint.hpp"
#include "submission/process_maps.hpp"

#include <turtle/implementation.hpp>
#include <turtle/observe.h>

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <netinet/tcp.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace {
constexpr bool server = TURTLE_SUBMISSION_SERVER == 1;
constexpr const char *role = server ? "server" : "client";

const char *env(const char *name) {
  const auto *value = std::getenv(name);
  return value ? value : "";
}

void require(bool ok, const char *what) {
  if (!ok)
    throw std::runtime_error(what);
}

class Socket {
  int fd_;

public:
  explicit Socket(int fd) : fd_(fd) { require(fd_ >= 0, "socket"); }
  ~Socket() {
    if (fd_ >= 0)
      close(fd_);
  }
  Socket(const Socket &) = delete;
  Socket(Socket &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  int get() const { return fd_; }
};

sockaddr_in address(const char *host, std::string_view port) {
  sockaddr_in a{};
  unsigned number = 0;
  auto end = port.data() + port.size();
  const auto parsed = std::from_chars(port.data(), end, number);
  require(parsed.ec == std::errc{} && parsed.ptr == end && number &&
              number <= 65535,
          "invalid port");
  a.sin_family = AF_INET;
  a.sin_port = htons(static_cast<unsigned short>(number));
  require(inet_pton(AF_INET, host, &a.sin_addr) == 1, "invalid IPv4 address");
  return a;
}

Socket connect_socket(const sockaddr_in &a) {
  Socket initial(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  const int s = initial.get();
  const auto *p = reinterpret_cast<const sockaddr *>(&a);
  if constexpr (server) {
    int enabled = 1;
    require(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof enabled) ==
                0,
            "socket options");
    require(bind(s, p, sizeof a) == 0 && listen(s, 1) == 0, "listen");
    int fd;
    do {
      fd = accept4(s, nullptr, nullptr, SOCK_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    require(fd >= 0, "accept");
    return Socket(fd);
  } else {
    require(connect(s, p, sizeof a) == 0, "connect");
    return initial;
  }
}

int configure_tcp(int fd) {
  const std::string_view policy = env("TURTLE_TCP_NODELAY");
  require(policy.empty() || policy == "on" || policy == "off",
          "invalid TURTLE_TCP_NODELAY (expected on or off)");
  const int requested = policy == "off" ? 0 : 1;
  require(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &requested,
                     sizeof requested) == 0,
          "could not set TCP_NODELAY");
  int effective = -1;
  socklen_t length = sizeof effective;
  require(getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &effective, &length) == 0 &&
              length == sizeof effective && effective == requested,
          "could not verify TCP_NODELAY");
  return effective;
}

turtle_result outcome(turtle_status result) {
  if (result == TURTLE_TLS_OK)
    return TURTLE_OK;
  return result == TURTLE_TLS_UNSUPPORTED ? TURTLE_UNSUPPORTED : TURTLE_ERROR;
}

turtle_result handshake(void *session, turtle_hs_point at) {
  if (at != TURTLE_LOCAL_COMPLETE)
    return TURTLE_UNSUPPORTED;
  auto *tls = static_cast<turtle_tls *>(session);
  return outcome(server ? turtle_tls_accept(tls, nullptr, 0)
                        : turtle_tls_connect(tls));
}

turtle_result accept_greeting(void *session, const void *data, size_t len) {
  return outcome(turtle_tls_accept(static_cast<turtle_tls *>(session),
                                   static_cast<const unsigned char *>(data),
                                   len));
}

turtle_result write_plain(void *session, turtle_hs_point at, const void *data,
                          size_t len, size_t *written) {
  if (at != TURTLE_LOCAL_COMPLETE)
    return TURTLE_UNSUPPORTED;
  auto n = turtle_app_send(static_cast<turtle_tls *>(session),
                           static_cast<const unsigned char *>(data), len);
  if (n <= 0 || static_cast<size_t>(n) > len)
    return TURTLE_ERROR;
  *written = static_cast<size_t>(n);
  return TURTLE_OK;
}

turtle_result read_plain(void *session, void *data, size_t len, size_t *read) {
  auto n = turtle_app_recv(static_cast<turtle_tls *>(session),
                           static_cast<unsigned char *>(data), len);
  if (n == 0)
    return TURTLE_CLOSED;
  if (n < 0 || static_cast<size_t>(n) > len)
    return TURTLE_ERROR;
  *read = static_cast<size_t>(n);
  return TURTLE_OK;
}

class Trace {
  struct Event {
    uint64_t ns;
    size_t bytes;
    bool sent;
  };

  struct Call {
    turtle_observe_stamp began{};
    size_t requested = 0;
  };
  std::array<Event, 16384> events_{};
  std::array<Call, 2> calls_{};
  const uint64_t owner_ = turtle_observe_clock().tid;
  size_t count_ = 0;
  bool covered_ = false;
  std::atomic<bool> invalid_{false};

  void fail() noexcept { invalid_.store(true, std::memory_order_relaxed); }

  bool on_owner_thread(uint64_t tid) noexcept {
    if (tid != 0 && tid == owner_)
      return !invalid_.load(std::memory_order_relaxed);
    fail();
    return false;
  }

  void record(bool sent, size_t bytes, uint64_t ns) noexcept {
    if (!ns || count_ == events_.size() || (count_ && ns < events_[count_ - 1].ns)) {
      fail();
      return;
    }
    events_[count_++] = {ns, bytes, sent};
  }

public:
  static void before_send(void *context, const unsigned char *, size_t bytes) {
    auto &trace = *static_cast<Trace *>(context);
    const auto stamp = turtle_observe_clock();
    if (trace.on_owner_thread(stamp.tid))
      trace.record(true, bytes, stamp.ns);
  }

  static void after_recv(void *context, const unsigned char *, size_t bytes) {
    auto &trace = *static_cast<Trace *>(context);
    const auto stamp = turtle_observe_clock();
    if (trace.on_owner_thread(stamp.tid))
      trace.record(false, bytes, stamp.ns);
  }

  static void coverage(void *context, int active) {
    auto &trace = *static_cast<Trace *>(context);
    if (!trace.on_owner_thread(turtle_observe_clock().tid))
      return;
    if ((active != 0 && active != 1) || (active != 0) == trace.covered_ ||
        trace.calls_[0].began.ns || trace.calls_[1].began.ns) {
      trace.fail();
      return;
    }
    trace.covered_ = active != 0;
    turtle_observe_coverage("library_io", active);
  }

  static void transfer_begin(void *context, int sent, size_t requested) {
    auto &trace = *static_cast<Trace *>(context);
    const auto stamp = turtle_observe_clock();
    if (!trace.on_owner_thread(stamp.tid))
      return;
    auto &call = trace.calls_[sent != 0];
    if (!trace.covered_ || call.began.ns || !stamp.ns) {
      trace.fail();
      return;
    }
    call = {stamp, requested};
    if (sent && requested)
      trace.record(true, requested, stamp.ns);
  }

  static void transfer_end(void *context, int sent, size_t requested,
                           ptrdiff_t result, const unsigned char *data) {
    auto &trace = *static_cast<Trace *>(context);
    const auto stamp = turtle_observe_clock();
    if (!trace.on_owner_thread(stamp.tid))
      return;
    auto &call = trace.calls_[sent != 0];
    if (!trace.covered_ || !call.began.ns || stamp.ns < call.began.ns ||
        requested != call.requested ||
        (result > 0 && static_cast<size_t>(result) > requested)) {
      trace.fail();
      return;
    }
    turtle_observe_io(call.began, stamp, "library_io", sent, requested, result,
                      data, 0);
    call = {};
    if (!sent && result > 0)
      trace.record(false, static_cast<size_t>(result), stamp.ns);
  }

  bool complete() const noexcept {
    return !invalid_.load(std::memory_order_relaxed) && !covered_;
  }

  size_t save(const std::string &path, bool completed) const {
    std::ofstream file(path);
    file << "event,monotonic_ns,bytes\n";
    bool send = false, recv = false;
    for (size_t i = 0; i < count_; ++i) {
      const auto &row = events_[i];
      file << (row.sent ? "before_send_offer" : "after_recv") << ',' << row.ns
           << ',' << row.bytes << '\n';
      send |= row.sent && row.bytes > 0;
      recv |= !row.sent && row.bytes > 0;
    }
    file.close();
    require(bool(file), "could not write transport trace");
    require(complete(), "transport trace incomplete");
    require(!completed || (send && recv), "transport hooks were not observed");
    return count_;
  }
};

std::string result_path(const char *directory) {
  std::string_view id = env("TURTLE_CONNECTION_ID");
  require(id.size() == 36 &&
              id.find_first_not_of("0123456789abcdef-") == id.npos,
          "missing or invalid TURTLE_CONNECTION_ID");
  require(std::filesystem::is_directory(directory),
          "invalid evidence directory");
  return (std::filesystem::path(directory) / (std::string(id) + "." + role))
      .string();
}

void save_maps(const std::string &path) {
  std::ifstream in("/proc/self/maps");
  std::ofstream out(path);
  require(turtle::submission::write_process_maps(in, out),
          "could not record process maps");
  out.close();
  require(bool(out), "could not close process maps");
}

int run(int argc, char **argv) {
  require(argc == 5, "expected HOST PORT EVIDENCE_DIR measured|peer");
  require(std::strcmp(env("TURTLE_ROLE"), role) == 0, "unexpected role");
  const std::string_view mode = argv[4];
  const bool measured = mode == "measured";
  require(measured || mode == "peer", "invalid measurement mode");
  const auto output = result_path(argv[3]);
  require(std::signal(SIGPIPE, SIG_IGN) != SIG_ERR, "signal setup");
  auto fd = connect_socket(address(argv[1], argv[2]));
  turtle_observe_fact("tcp_nodelay", configure_tcp(fd.get()));
  const char *name = env("TURTLE_PEER_NAME");
  const char *cert = env("TURTLE_CERT");
  const bool mutual = server ? *name != '\0' : *cert != '\0';
  const turtle_tls_config config{server ? TURTLE_SERVER : TURTLE_CLIENT,
                                 mutual ? TURTLE_MUTUAL_AUTH
                                        : TURTLE_SERVER_AUTH,
                                 env("TURTLE_CA"),
                                 cert,
                                 env("TURTLE_KEY"),
                                 name};
  auto trace = measured ? std::make_unique<Trace>() : nullptr;
  const turtle_transport_hooks hooks{
      trace.get(), Trace::before_send, Trace::after_recv, Trace::coverage,
      Trace::transfer_begin, Trace::transfer_end};
  std::unique_ptr<turtle_tls, decltype(&turtle_tls_free)> tls(
      turtle_tls_setup(&config, fd.get()), turtle_tls_free);
  require(tls != nullptr, "TLS setup");
  if (measured) {
    const auto binding = turtle_tls_set_hooks(tls.get(), &hooks);
    if (binding != TURTLE_TLS_OK) {
      if (binding == TURTLE_TLS_UNSUPPORTED)
        turtle_observe_fact("endpoint_unsupported", 1);
      throw std::runtime_error("could not install measured transport hooks");
    }
  }

  const turtle_endpoint endpoint{tls.get(), handshake, write_plain, read_plain};
  const auto result = turtle_observe_run_submission_endpoint(
      &endpoint, server ? accept_greeting : nullptr);
  // The endpoint result is known. A partial artifact must not qualify as
  // evidence, and a failed capture must not replace that result.
  const auto capture = [&](const char *suffix, const auto &write) {
    try {
      const auto path = output + suffix;
      const auto partial = path + ".partial";
      write(partial);
      std::filesystem::rename(partial, path);
      return true;
    } catch (const std::exception &error) {
      std::fprintf(stderr, "submission %s: evidence %s: %s\n", role, suffix,
                   error.what());
      return false;
    }
  };
  if (measured) {
    size_t rows = 0;
    bool detached = false;
    const bool saved = capture(".csv", [&](const std::string &partial) {
      detached = turtle_tls_set_hooks(tls.get(), nullptr) == TURTLE_TLS_OK;
      require(detached, "could not detach transport hooks");
      rows = trace->save(partial, result == TURTLE_OK);
    });
    if (!detached || !trace->complete())
      turtle_observe_fact("transport_observation_incomplete", 1);
    if (saved && rows != 0) {
      // Publish only after the corresponding complete CSV has been committed.
      capture(".csv.count", [&](const std::string &partial) {
        std::ofstream count(partial);
        count << rows << '\n';
        count.close();
        require(bool(count), "could not write transport count");
      });
    }
  }
  capture(".maps", save_maps);
  if (result == TURTLE_UNSUPPORTED)
    std::fprintf(stderr, "submission %s: TLS operation unsupported\n", role);
  else if (result != TURTLE_OK)
    std::fprintf(stderr, "submission %s: TLS task failed (%d)\n", role,
                 static_cast<int>(result));
  return result == TURTLE_OK ? 0 : 1;
}
}

int main(int argc, char **argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception &e) {
    std::fprintf(stderr, "submission %s: %s\n", role, e.what());
    return 1;
  }
}
