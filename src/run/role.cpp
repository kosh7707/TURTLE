#include "artifact/endpoint.hpp"
#include "artifact/json.hpp"
#include "net/transport.hpp"
#include "run/runner.hpp"
#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <turtle/role.h>
#include <unistd.h>

namespace {
using namespace turtle;
using namespace measure;
void need(bool yes, const char *reason) {
  if (!yes)
    throw std::runtime_error(reason);
}
std::string command() {
  std::string s;
  need(bool(std::getline(std::cin, s)), "control_closed");
  return s;
}
Mode mode(const run::Options &o) {
  if ((o.role == TURTLE_CLIENT) != (o.measured_role == "client"))
    return Mode::peer;
  if (o.recording == "off")
    return Mode::off;
  return o.recording == "basic" ? Mode::basic : Mode::detailed;
}
// Determine the full plaintext ClientHello boundary from actually submitted
// ciphertext; do not assume one handshake per TLSPlaintext record or send.
bool complete_ch(const std::vector<unsigned char> &bytes) {
  size_t pos = 0, hs = 0, wanted = 0;
  unsigned char header[4]{};
  while (pos + 5 <= bytes.size()) {
    if (bytes[pos] != 22 || bytes[pos + 1] != 3)
      return false;
    size_t len = (size_t(bytes[pos + 3]) << 8) | bytes[pos + 4];
    pos += 5;
    if (!len || pos + len > bytes.size())
      return false;
    for (size_t i = 0; i < len; ++i) {
      if (hs < 4)
        header[hs] = bytes[pos + i];
      if (++hs == 4) {
        if (header[0] != 1)
          return false;
        wanted = 4 + (size_t(header[1]) << 16) + (size_t(header[2]) << 8) +
                 header[3];
      }
    }
    pos += len;
    if (wanted && hs >= wanted) {
      static constexpr unsigned char ccs[] = {20, 3, 3, 0, 1, 1};
      return wanted >= 4 + 41 && hs == wanted &&
             (pos == bytes.size() ||
              std::equal(bytes.begin() + pos, bytes.end(), std::begin(ccs),
                         std::end(ccs)));
    }
  }
  return false;
}
Operation operation(turtle_op op) {
  switch (op) {
  case TURTLE_HS:
  case TURTLE_FIRST_HS:
    return Operation::handshake;
  case TURTLE_FIRST_WRITE:
    return Operation::server_first;
  case TURTLE_READ:
    return Operation::read;
  case TURTLE_WRITE:
    return Operation::write;
  case TURTLE_SHUTDOWN:
    return Operation::shutdown;
  default:
    return Operation::none;
  }
}
} // namespace
struct turtle_session {
  run::Options o;
  turtle_config cfg;
  artifact::Result r;
  measure::Recorder rec;
  std::unique_ptr<net::Connection> conn;
  turtle_transport raw{};
  turtle_io_boundary counts{};
  enum WireMode { unset, bytes_only, intervals, builtin } wire_mode = unset;
  bool lower_pending = false, lower_sending = false;
  const void *lower_data = nullptr;
  size_t lower_size = 0;
  frame::SocketObservation lower;
  bool has_first, offline_io = false, ready = false, files = false;
  bool image_barrier = false;
  bool first_hs = false, hs = false, finishing = false, done = false,
       started = false, alternate = false;
  unsigned hooks;
  enum Phase { idle, pulled, calling, returned } phase = idle;
  turtle_action act{};
  size_t event = 0, sent = 0, received = 0, first_sent = 0;
  size_t verified = 0;
  std::string input, output;
  std::vector<unsigned char> readbuf, ch;
  uint64_t wire_sent = 0;
  measure::Stamp stop;
  // Each direction has a separate stable buffer and retry descriptor.
  struct Retry {
    bool pending = false, write = false, other = false;
    turtle_action a{};
  };
  Retry stalled[2];
  int lane(turtle_op op) const { return op == TURTLE_READ ? 1 : 0; }
  bool client() const { return o.role == TURTLE_CLIENT; }
  bool early() const { return o.scenario == "S2" || o.scenario == "S4"; }
  bool request() const {
    return o.scenario == "S1" || o.scenario == "S3" || o.scenario == "S4";
  }
  bool response() const { return o.scenario == "S3" || o.scenario == "S4"; }
  bool probe() const { return o.purpose == "capability"; }
  turtle_session(run::Options opts, const char *name, unsigned h, bool first)
      : o(std::move(opts)), cfg{o.role,
                                o.auth == "mtls",
                                o.check,
                                o.host.c_str(),
                                o.port,
                                static_cast<int>(o.arguments.size()),
                                o.arguments.data()},
        rec(Recorder::event_capacity, o.perf_counters, mode(o)),
        has_first(first), hooks(h) {
    r.role_sdk = true;
    r.role = client() ? "client" : "server";
    r.auth = o.auth;
    r.purpose = o.purpose;
    r.implementation = name;
    r.scenario = o.scenario;
    r.measured_role = o.measured_role;
    r.recording = o.recording;
    r.run_id = r.connection_id = o.run_id;
    r.chunk = o.chunk;
    r.cpu_samples = o.cpu_samples && mode(o) != Mode::peer;
    r.request_bytes = o.request.size();
    r.response_bytes = o.response.size();
    r.greeting_bytes = o.greeting.size();
    if (client()) {
      if (early())
        input = o.greeting;
      if (response())
        input += o.response;
      if (request())
        output = o.request;
    } else {
      if (request())
        input = o.request;
      if (response())
        output = o.response;
    }
    readbuf.resize(input.size());
    if (!o.check) {
      std::filesystem::create_directories(o.output);
      for (auto f :
           {"endpoint.json", "events.jsonl", "counters.json", "tls_send.bin",
            "tls_receive.bin", "wire_send.bin", "wire_receive.bin"})
        need(!std::filesystem::exists(std::filesystem::path(o.output) / f),
             "output_already_exists");
      files = true;
    }
  }
  void fail(const char *s) {
    if (r.scenario_complete)
      r.shutdown_reason = s;
    else if (r.invalid_reason.empty())
      r.invalid_reason = s;
  }
  void wire(bool tx, const void *data, size_t n, bool external) {
    if (external && rec.detailed())
      rec.capture(tx ? Direction::send : Direction::receive, data, n);
    if (!tx || !probe())
      return;
    wire_sent += n;
    if (client() && !r.client_paused) {
      need(n <= 1024 * 1024 - ch.size(), "probe_client_hello_too_large");
      const auto *p = static_cast<const unsigned char *>(data);
      ch.insert(ch.end(), p, p + n);
    }
  }
  void report_facts(const turtle_handshake_info *f) {
    need(f, "missing_handshake_facts");
    need(f->version == TURTLE_TLS13 && f->resumed == 0, "not_full_tls13");
    need(f->profile == (cfg.mutual_auth ? TURTLE_PROFILE_MTLS_1RTT
                                        : TURTLE_PROFILE_SERVER_AUTH_1RTT),
         "authentication_policy_mismatch");
    need(f->peer_verified == (client() || cfg.mutual_auth ? 1 : 0),
         "peer_not_authenticated");
    r.version = f->version;
    r.resumed = f->resumed;
    r.profile = f->profile;
    r.peer_verified = f->peer_verified;
    r.record_policy = f->record_policy;
    if (f->cipher)
      r.cipher = f->cipher;
    if (f->group)
      r.group = f->group;
    hs = true;
  }
  void mark_end(const Stamp &stamp, size_t id) {
    r.end = stamp;
    r.end_event = id;
  }
  void freeze_client() {
    need(complete_ch(ch), "probe_incomplete_client_hello");
    r.client_hello_bytes = ch.size();
    r.client_paused = true;
    std::cout << "PAUSED" << std::endl;
    const auto s = command();
    need(s.starts_with("RESUME "), "probe_resume_expected");
    auto [p, e] =
        std::from_chars(s.data() + 7, s.data() + s.size(), r.server_submitted);
    need(e == std::errc{} && p == s.data() + s.size() && r.server_submitted > 0,
         "probe_invalid_byte_count");
    r.queued_before_resume = conn->queued(r.server_submitted);
  }
  size_t limit(size_t n) const {
    return o.app_chunk ? std::min(n, o.app_chunk) : n;
  }
  turtle_action pull() {
    need(ready && phase == idle && r.invalid_reason.empty(),
         "pull_out_of_order");
    if (done)
      return {TURTLE_DONE, nullptr, nullptr, 0};
    turtle_action a{};
    if (!client() && early() && !first_hs)
      a.op = TURTLE_FIRST_HS;
    else if (!client() && early() && first_sent < o.greeting.size()) {
      a = {TURTLE_FIRST_WRITE, o.greeting.data() + first_sent, nullptr,
           limit(o.greeting.size() - first_sent)};
    } else if (!hs)
      a.op = TURTLE_HS;
    else {
      bool can_write =
          sent < output.size() && (client() || verified == input.size());
      bool can_read = received < input.size();
      if (can_write && can_read && (stalled[1].pending || stalled[0].pending)) {
        if (stalled[0].pending && stalled[1].pending) {
          auto mask = conn->wait_either(stalled[0].write, stalled[1].write);
          alternate = !(mask & 1);
        } else if (stalled[0].pending)
          alternate = stalled[0].other;
        else
          alternate = !stalled[1].other;
      }
      if (can_write && (!can_read || !alternate))
        a = {TURTLE_WRITE, output.data() + sent, nullptr,
             limit(output.size() - sent)};
      else if (can_read)
        a = {TURTLE_READ, nullptr, readbuf.data() + received,
             limit(input.size() - received)};
      else {
        need(sent == output.size() && verified == input.size(),
             "application_incomplete");
        if (!finishing) {
          if (r.role == o.measured_role)
            need(r.counts_bound && r.send_attempts && r.positive_receives,
                 "missing_transport_counts");
          finishing = true;
          r.content_verified = r.scenario_complete = true;
          r.scenario_observations_complete = rec.complete();
          r.scenario_tls_send = r.scenario_wire_send =
              rec.total(Layer::wire, Direction::send);
          r.scenario_tls_receive = r.scenario_wire_receive =
              rec.total(Layer::wire, Direction::receive);
          r.shutdown = "failed";
        }
        a.op = TURTLE_SHUTDOWN;
      }
    }
    if (a.op == TURTLE_READ || a.op == TURTLE_WRITE)
      stalled[1 - lane(a.op)].other = false;
    auto &retry = stalled[lane(a.op)];
    if (retry.pending) {
      need(a.op == retry.a.op && a.in == retry.a.in && a.out == retry.a.out &&
               a.size == retry.a.size,
           "unstable_retry");
      conn->wait(retry.write);
      retry.pending = false;
    }
    phase = pulled;
    return act = a;
  }
  void submit(turtle_result s, const turtle_handshake_info *f) {
    need(phase == returned, "submit_without_return");
    phase = idle;
    bool ok = s.status == TURTLE_OK;
    const bool data = act.op == TURTLE_READ || act.op == TURTLE_WRITE ||
                      act.op == TURTLE_FIRST_WRITE;
    need(ok && data ? s.bytes > 0 && s.bytes <= act.size : s.bytes == 0,
         "invalid_progress");
    if (event) {
      auto &e = rec.event(event);
      e.success = ok;
      e.transferred = ok ? static_cast<ptrdiff_t>(data ? s.bytes : 1)
                      : s.status == TURTLE_AGAIN_READ  ? TURTLE_WANT_READ
                      : s.status == TURTLE_AGAIN_WRITE ? TURTLE_WANT_WRITE
                      : s.status == TURTLE_EOF         ? 0
                                                       : -1;
      if (data) {
        e.plaintext_begin =
            act.op == TURTLE_READ ? r.plaintext_received : r.plaintext_sent;
        e.plaintext_end = e.plaintext_begin + s.bytes;
      }
    }
    if (s.status == TURTLE_AGAIN_READ || s.status == TURTLE_AGAIN_WRITE) {
      need(!f, "unexpected_handshake_facts");
      bool writing = s.status == TURTLE_AGAIN_WRITE;
      stalled[lane(act.op)] = {true, writing, s.allow_other != 0, act};
      if (probe() && client() && act.op == TURTLE_HS && !writing &&
          !r.client_paused)
        freeze_client();
      return;
    }
    if (act.op == TURTLE_SHUTDOWN) {
      r.shutdown = ok ? "ok" : "failed";
      if (!ok)
        r.shutdown_reason = "tls_shutdown_failed";
      done = true;
      return;
    }
    need(ok, act.op == TURTLE_READ          ? "application_read_failed"
             : act.op == TURTLE_WRITE       ? "application_write_failed"
             : act.op == TURTLE_FIRST_WRITE ? "server_first_failed"
                                            : "handshake_failed");
    need(!f || act.op == TURTLE_HS || act.op == TURTLE_FIRST_HS,
         "unexpected_handshake_facts");
    if (act.op == TURTLE_HS || act.op == TURTLE_FIRST_HS) {
      if (act.op == TURTLE_FIRST_HS) {
        first_hs = true;
        r.presend_begin = wire_sent;
        need(!probe() || !f, "probe_handshake_completed_before_presend");
      }
      if (act.op == TURTLE_HS || f)
        report_facts(f);
      if (o.scenario == "S0" && hs)
        mark_end(stop, event);
    } else if (act.op == TURTLE_FIRST_WRITE) {
      first_sent += s.bytes;
      r.plaintext_sent += s.bytes;
      if (first_sent == o.greeting.size()) {
        if (o.scenario == "S2")
          mark_end(stop, event);
        if (probe()) {
          r.server_submitted = wire_sent;
          need(r.server_submitted > r.presend_begin,
               "probe_no_greeting_submission");
          r.server_presend = true;
          std::cout << "PRESEND " << wire_sent << std::endl;
          need(command() == "CONTINUE", "probe_release_expected");
        }
      }
    } else if (act.op == TURTLE_WRITE) {
      sent += s.bytes;
      r.plaintext_sent += s.bytes;
      alternate = client() && early() && received < o.greeting.size() &&
                  conn->readable();
      if (sent == output.size() && (!client() || o.scenario == "S1"))
        mark_end(stop, event);
    } else {
      size_t begin = received;
      received += s.bytes;
      r.plaintext_received += s.bytes;
      alternate = false;
      const size_t target = o.scenario == "S4" ? o.greeting.size() : 0;
      if (client() && begin <= target && target < received)
        mark_end(stop, event);
      while (verified < input.size()) {
        auto boundary =
            client() && early() && !verified ? o.greeting.size() : input.size();
        if (received < boundary)
          break;
        const auto id = rec.begin(Kind::call, Operation::verify,
                                  Direction::receive, 0, boundary - verified);
        const bool match =
            std::equal(input.begin() + verified, input.begin() + boundary,
                       readbuf.begin() + verified, [](char a, unsigned char b) {
                         return static_cast<unsigned char>(a) == b;
                       });
        auto verified_at = rec.end(id, match);
        if (id) {
          rec.event(id).plaintext_begin = verified;
          rec.event(id).plaintext_end = boundary;
        }
        need(match, "application_content_mismatch");
        verified = boundary;
        if (!client() && !response())
          mark_end(verified_at, id);
        if (client() && early() && probe() && verified == o.greeting.size())
          std::cout << "GREETING" << std::endl;
      }
    }
  }
};

namespace {
struct PreserveErrno {
  int value = errno;
  ~PreserveErrno() { errno = value; }
};
template <class F> int checked(turtle_session *s, F fn) noexcept {
  PreserveErrno guard;
  if (!s)
    return -1;
  try {
    fn();
    return 1;
  } catch (const std::exception &e) {
    s->fail(e.what());
  } catch (...) {
    s->fail("sdk_exception");
  }
  return -1;
}
void install_lower_counts(turtle_session *s) {
  if (!s->conn)
    return;
  turtle_io_hooks hooks{};
  if (s->wire_mode == turtle_session::builtin && s->r.counts_bound &&
      !s->counts.set_hooks)
    hooks = {
        s, [](void *p) { ++static_cast<turtle_session *>(p)->r.send_attempts; },
        [](void *p) {
          ++static_cast<turtle_session *>(p)->r.positive_receives;
        }};
  s->conn->count_hooks(hooks);
}
void attach(turtle_session *s, net::Socket fd) {
  need(!s->conn && !s->ready && !s->o.check, "socket_already_attached");
  s->conn = std::make_unique<net::Connection>(std::move(fd), s->rec, s->o.chunk,
                                              s->o.timeout, s->probe());
  s->raw = s->conn->transport();
}
} // namespace
void turtle::run::mark_legacy(turtle_session *s) { s->r.role_sdk = false; }
extern "C" turtle_session *turtle_session_open(int argc, char **argv,
                                               const char *name, unsigned hooks,
                                               int server_first) {
  try {
    need(name && *name, "missing_implementation_name");
    return new turtle_session(run::options(argc, argv), name, hooks,
                              server_first != 0);
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return nullptr;
  }
}
extern "C" const turtle_config *turtle_session_config(const turtle_session *s) {
  return s ? &s->cfg : nullptr;
}
extern "C" int turtle_session_bound(turtle_session *s, uint16_t port) {
  return checked(s, [&] {
    need(!s->client() && !s->ready && !s->conn && port, "invalid_listen_port");
    std::cout << "LISTEN " << port << std::endl;
  });
}
extern "C" int turtle_session_attach(turtle_session *s, int fd) {
  return checked(s, [&] {
    net::Socket copy(dup(fd));
    need(copy.get() >= 0, "invalid_socket");
    attach(s, std::move(copy));
  });
}
extern "C" int turtle_session_bind_counts(turtle_session *s,
                                          const turtle_io_boundary *b) {
  return checked(s, [&] {
    if (s->counts.set_hooks)
      s->counts.set_hooks(s->counts.transport, {});
    s->counts = {};
    if (b) {
      need(!s->ready && b->set_hooks, "invalid_count_binding");
      if (s->r.role != s->o.measured_role)
        return;
      s->counts = *b;
      b->set_hooks(
          b->transport,
          {s,
           [](void *p) { ++static_cast<turtle_session *>(p)->r.send_attempts; },
           [](void *p) {
             ++static_cast<turtle_session *>(p)->r.positive_receives;
           }});
      s->r.counts_bound = true;
    }
    install_lower_counts(s);
  });
}
extern "C" int turtle_session_wire(turtle_session *s, int sending,
                                   const void *data, size_t n) {
  return checked(s, [&] {
    need(data && n && (sending == 0 || sending == 1), "invalid_wire_transfer");
    need(s->wire_mode == turtle_session::unset ||
             s->wire_mode == turtle_session::bytes_only,
         "mixed_wire_sources");
    s->wire_mode = turtle_session::bytes_only;
    s->wire(sending, data, n, true);
  });
}
extern "C" int turtle_socket_before(turtle_session *s, int tx, const void *buf,
                                    size_t n) {
  return checked(s, [&] {
    need(s->phase == turtle_session::calling && !s->lower_pending &&
             (tx == 0 || tx == 1) && (buf || !n),
         "socket_entry_out_of_order");
    need(s->wire_mode == turtle_session::unset ||
             s->wire_mode == turtle_session::intervals,
         "mixed_wire_sources");
    s->wire_mode = turtle_session::intervals;
    s->lower_pending = true;
    s->lower_sending = tx;
    s->lower_data = buf;
    s->lower_size = n;
    s->lower.begin(s->rec, tx, n, s->rec.active_call());
  });
}
extern "C" int turtle_socket_returned(turtle_session *s, ptrdiff_t raw) {
  const int error = errno;
  return checked(s, [&] {
    need(s->lower_pending, "socket_return_without_entry");
    s->lower.end(s->rec, s->lower_sending, s->lower_data, s->lower_size, raw,
                 error);
    s->lower_pending = false;
    need(raw >= -1 && (raw <= 0 || static_cast<size_t>(raw) <= s->lower_size),
         "invalid_socket_result");
    if (raw > 0)
      s->wire(s->lower_sending, s->lower_data, raw, false);
  });
}
extern "C" int turtle_session_transport(turtle_session *s,
                                        turtle_transport *out) {
  return checked(s, [&] {
    need(out && !s->ready, "invalid_transport_request");
    need(s->wire_mode == turtle_session::unset ||
             s->wire_mode == turtle_session::builtin,
         "mixed_wire_sources");
    s->wire_mode = turtle_session::builtin;
    if (!s->o.check && !s->conn) {
      if (s->client())
        attach(s, net::connect(s->cfg.host, s->cfg.port));
      else {
        auto listener = net::listen(s->cfg.host, s->cfg.port);
        need(turtle_session_bound(s, net::port(listener)) == 1,
             "listen_failed");
        attach(s, net::accept(listener));
      }
    }
    s->r.counts_bound =
        s->r.role == s->o.measured_role; // the installed wrapper is the
                                         // TLS/lower-I/O boundary
    install_lower_counts(s);
    *out = {s,
            [](void *p, void *buf, size_t n) -> ptrdiff_t {
              auto &x = *static_cast<turtle_session *>(p);
              if (x.o.check) {
                x.offline_io = true;
                return -1;
              }
              auto rc = x.raw.receive(x.raw.state, buf, n);
              return rc;
            },
            [](void *p, const void *buf, size_t n) -> ptrdiff_t {
              auto &x = *static_cast<turtle_session *>(p);
              if (x.o.check) {
                x.offline_io = true;
                return -1;
              }
              auto rc = x.raw.send(x.raw.state, buf, n);
              PreserveErrno guard;
              if (rc > 0 && checked(&x, [&] {
                              x.wire(true, buf, static_cast<size_t>(rc), false);
                            }) < 0)
                return -1;
              return rc;
            },
            nullptr, s->cfg.mutual_auth};
    if (s->raw.observe)
      out->observe = [](void *p, turtle_hook hook, int tx, const void *buf,
                        size_t n, ptrdiff_t rc) {
        PreserveErrno guard;
        auto &x = *static_cast<turtle_session *>(p);
        x.raw.observe(x.raw.state, hook, tx, buf, n, rc);
      };
  });
}
extern "C" int turtle_session_ready(turtle_session *s, int prepared) {
  int rc = checked(s, [&] {
    need(!s->ready, "ready_already_called");
    bool clock = measure::now().wall_available;
    const bool measured = s->r.role == s->o.measured_role;
    const char *err = nullptr;
    if (!prepared)
      err = "prepare_failed";
    else if (s->offline_io)
      err = "unexpected_prepare_io";
    else if (measured && !clock)
      err = "monotonic_clock_unavailable";
    else if (!s->client() && s->early() && !s->has_first)
      err = "server_first_unsupported";
    else if (measured && !s->r.counts_bound)
      err = "transport_boundary_unbound";
    if (s->o.check) {
      const auto &pmu = s->rec.counters();
      auto has = [&](turtle_hook h) { return (s->hooks & (1u << h)) != 0; };
      artifact::Json j{
          {"ready", !err},
          {"implementation", s->r.implementation},
          {"monotonic_clock", clock},
          {"server_first", s->has_first},
          {"public_io", (has(TURTLE_BIO_BEGIN) && has(TURTLE_BIO_END)) ||
                            (has(TURTLE_IO_BEGIN) && has(TURTLE_IO_END))},
          {"headers", has(TURTLE_RECORD_HEADER)},
          {"perf_counters", pmu.availability() == PerfAvailability::available},
          {"perf_reason", pmu.reason() ? artifact::Json(pmu.reason())
                                       : artifact::Json(nullptr)}};
      if (err)
        j["reason"] = err;
      std::cout << j.dump() << std::endl;
    }
    if (err)
      throw std::runtime_error(err);
    if (!s->o.check) {
      need(s->conn != nullptr, "connected_socket_required");
      s->image_barrier =
          s->o.controlled && std::getenv("TURTLE_IMAGE_BARRIER") &&
          std::string_view(std::getenv("TURTLE_IMAGE_BARRIER")) == "1";
      if (s->image_barrier)
        artifact::save(std::filesystem::path(s->o.output) / "participant.json",
                       {{"pid", ::getpid()}, {"run_id", s->o.run_id}});
      std::cout << "READY" << std::endl;
      need(command() == "START", "start_barrier_failed");
    }
    s->ready = true;
  });
  return rc == 1 && s->o.check ? 0 : rc;
}
extern "C" int turtle_pull(turtle_session *s, turtle_action *a) {
  return checked(s, [&] {
    need(a && !s->o.check, "invalid_pull");
    *a = s->pull();
  });
}
extern "C" void turtle_before(turtle_session *s) {
  checked(s, [&] {
    need(s->phase == turtle_session::pulled, "before_out_of_order");
    s->phase = turtle_session::calling;
    bool tx = s->act.op == TURTLE_FIRST_WRITE || s->act.op == TURTLE_WRITE;
    s->event =
        s->rec.begin(Kind::call, operation(s->act.op),
                     tx ? Direction::send : Direction::receive, 0, s->act.size);
    if (!s->started) {
      s->started = true;
      s->r.begin_event = s->event;
      s->r.begin = s->event ? s->rec.event(s->event).begin : s->rec.stamp();
    }
  });
}
extern "C" void turtle_returned(turtle_session *s) {
  checked(s, [&] {
    need(s->phase == turtle_session::calling, "return_out_of_order");
    need(!s->lower_pending, "unclosed_socket_interval");
    s->stop = s->rec.end(s->event, false, 0);
    s->phase = turtle_session::returned;
  });
}
extern "C" int turtle_submit(turtle_session *s, turtle_result r,
                             const turtle_handshake_info *f) {
  return checked(s, [&] {
    need(s->r.invalid_reason.empty(), "session_failed");
    s->submit(r, f);
  });
}
extern "C" int turtle_session_close(turtle_session *ep) {
  std::unique_ptr<turtle_session> s(ep);
  if (!s)
    return 1;
  try {
    if (s->counts.set_hooks)
      s->counts.set_hooks(s->counts.transport, {});
    if (s->o.check)
      return s->ready && s->r.invalid_reason.empty() ? 0 : 1;
    if (!s->r.scenario_complete && s->r.invalid_reason.empty())
      s->fail("session_incomplete");
    if (s->rec.reason())
      s->r.observation_reason = s->rec.reason();
    if (s->files)
      artifact::write(s->o.output, s->rec, s->r);
    if (s->ready && s->image_barrier) {
      std::cout << "IMAGES_DONE" << std::endl;
      need(command() == "EXIT", "image_release_expected");
    }
    return s->r.scenario_complete && s->r.invalid_reason.empty() ? 0 : 1;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
