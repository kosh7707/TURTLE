#include "measure/perf.hpp"
#include "native/endpoint_observe.hpp"
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <nlohmann/json.hpp>
#include <signal.h>
#include <string>
#include <sys/syscall.h>
#include <turtle/observe.h>
#include <unistd.h>

namespace {
using Json = nlohmann::json;
const char *env(const char *key) {
  auto s = std::getenv(key);
  return s ? s : "";
}
int evidence_fd() {
  const char *s = env("TURTLE_EVIDENCE_FD");
  int fd = -1;
  const char *end = s + std::strlen(s);
  auto parsed = std::from_chars(s, end, fd);
  return parsed.ec == std::errc{} && parsed.ptr == end && fd > 2 ? fd : -1;
}
const int fd = evidence_fd();
std::mutex serial;
uint64_t sequence = 0;
bool lost = false;
uint64_t now() {
  timespec t{};
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    return 0;
  return uint64_t(t.tv_sec) * 1000000000 + t.tv_nsec;
}
std::string hex(const void *p, size_t n) {
  const auto *b = static_cast<const unsigned char *>(p);
  std::string out(n * 2, '0');
  for (size_t i = 0; i < n; ++i) {
    constexpr char digits[] = "0123456789abcdef";
    out[2 * i] = digits[b[i] >> 4];
    out[2 * i + 1] = digits[b[i] & 15];
  }
  return out;
}
// SIGPIPE must not change native application behavior if the reader goes away.
bool transmit(const std::string &bytes) {
  sigset_t sig, old, pending;
  sigemptyset(&sig);
  sigaddset(&sig, SIGPIPE);
  if (pthread_sigmask(SIG_BLOCK, &sig, &old))
    return false;
  sigpending(&pending);
  size_t n = 0;
  while (n < bytes.size()) {
    auto r = write(fd, bytes.data() + n, bytes.size() - n);
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0) {
      if (r < 0 && errno == EPIPE && !sigismember(&pending, SIGPIPE)) {
        timespec zero{};
        while (sigtimedwait(&sig, nullptr, &zero) < 0 && errno == EINTR) {
        }
      }
      break;
    }
    n += size_t(r);
  }
  pthread_sigmask(SIG_SETMASK, &old, nullptr);
  return n == bytes.size();
}
struct PreserveErrno {
  int saved = errno;
  ~PreserveErrno() { errno = saved; }
};
template <class F> uint64_t emit(turtle_observe_stamp t, F fields) noexcept {
  PreserveErrno keep;
  if (fd < 0)
    return 0;
  try {
    std::lock_guard lock(serial);
    if (lost)
      return 0;
    Json j = {{"v", 1},
              {"seq", ++sequence},
              {"role", env("TURTLE_ROLE")},
              {"run_id", env("TURTLE_RUN_ID")},
              {"connection_id", env("TURTLE_CONNECTION_ID")},
              {"pid", getpid()},
              {"tid", t.tid},
              {"ns", t.ns},
              {"pmu", nullptr},
              {"pmu_status", t.pmu_status ? t.pmu_status : "unavailable"},
              {"pmu_reason", t.pmu_reason ? Json(t.pmu_reason) : Json(nullptr)},
              {"pmu_errno", t.pmu_errno}};
    if (t.pmu_available ||
        (t.pmu_status && std::strcmp(t.pmu_status, "partial") == 0 &&
         t.cycles_id))
      j["pmu"] = {{"cycles", t.cycles},
                  {"instructions",
                   t.pmu_available ? Json(t.instructions) : Json(nullptr)},
                  {"enabled_ns", t.enabled_ns},
                  {"running_ns", t.running_ns},
                  {"read_begin_ns", t.read_begin_ns},
                  {"read_end_ns", t.read_end_ns},
                  {"cycles_id", t.cycles_id},
                  {"instructions_id",
                   t.pmu_available ? Json(t.instructions_id) : Json(nullptr)},
                  {"type", "PERF_TYPE_HARDWARE"},
                  {"cycles_config", "PERF_COUNT_HW_CPU_CYCLES"},
                  {"instructions_config",
                   t.pmu_available ? Json("PERF_COUNT_HW_INSTRUCTIONS")
                                   : Json(nullptr)}};
    j.update(fields());
    auto line = j.dump() + "\n";
    if (line.size() > 3 * 1024 * 1024 || !transmit(line))
      lost = true;
    return lost ? 0 : sequence;
  } catch (
      ...) { /* A missing sequence invalidates the evidence, not the app. */
    return 0;
  }
}
Json str(const char *p) { return p ? Json(p) : Json(nullptr); }
Json event(const char *name) {
  return {{"kind", "event"}, {"name", str(name)}, {"message", nullptr},
          {"offset", 0}, {"length", 0}};
}
} // namespace
extern "C" turtle_observe_stamp turtle_observe_now(void) {
  PreserveErrno keep;
  if (fd < 0)
    return {};
  thread_local turtle::measure::PerfCounters perf(
      std::strcmp(env("TURTLE_PMU"), "1") == 0, true);
  auto ns = now();
  auto p = perf.snapshot();
  return {ns,
          uint64_t(syscall(SYS_gettid)),
          p.cycles,
          p.instructions,
          p.enabled_ns,
          p.running_ns,
          p.read_begin_ns,
          p.read_end_ns,
          perf.ids()[0],
          perf.ids()[1],
          int(p.available),
          perf.error_number(),
          turtle::measure::name(perf.availability()),
          perf.reason()};
}
extern "C" void turtle_observe_event_at(turtle_observe_stamp t,
                                        const char *name) {
  emit(t, [&] { return event(name); });
}
extern "C" void turtle_observe_event(const char *n) {
  turtle_observe_event_at(turtle_observe_now(), n);
}
extern "C" void turtle_observe_fact(const char *n, int v) {
  emit(turtle_observe_now(), [&] {
    return Json{{"kind", "fact"},
                {"name", str(n)},
                {"value", v == -1            ? Json(nullptr)
                          : v == 0 || v == 1 ? Json(bool(v))
                                             : Json(v)}};
  });
}
extern "C" void turtle_observe_identity(unsigned version, unsigned suite,
                                        unsigned group, const char *peer) {
  emit(turtle_observe_now(), [&] {
    return Json{{"kind", "identity"},
                {"version", version},
                {"suite", suite},
                {"group", group},
                {"peer_name", str(peer)}};
  });
}
extern "C" void turtle_observe_coverage(const char *s, int active) {
  emit(turtle_observe_now(), [&] {
    return Json{
        {"kind", "coverage"}, {"source", str(s)}, {"active", bool(active)}};
  });
}
extern "C" void turtle_observe_io(turtle_observe_stamp b,
                                  turtle_observe_stamp e, const char *s,
                                  int sent, size_t req, int64_t result,
                                  const void *data, int peek) {
  emit(e, [&] {
    return Json{{"kind", "io"},
                {"begin_ns", b.ns},
                {"begin_tid", b.tid},
                {"source", str(s)},
                {"sent", bool(sent)},
                {"requested", req},
                {"result", result},
                {"peek", bool(peek)},
                {"hex", data && result > 0 && uint64_t(result) <= req &&
                                result <= 1048576
                            ? Json(hex(data, result))
                            : Json(nullptr)}};
  });
}
extern "C" void turtle_observe_bytes(int sent, const void *data, size_t len) {
  emit(turtle_observe_now(), [&] {
    return Json{
        {"kind", "bytes"},
        {"source", "stream"},
        {"sent", bool(sent)},
        {"length", len},
        {"hex", data && len <= 1048576 ? Json(hex(data, len)) : Json(nullptr)}};
  });
}
extern "C" void turtle_observe_header(int sent, uint64_t offset,
                                      const void *data) {
  emit(turtle_observe_now(), [&] {
    return Json{{"kind", "header"},
                {"sent", bool(sent)},
                {"offset", offset},
                {"hex", data ? Json(hex(data, 5)) : Json(nullptr)}};
  });
}
extern "C" void turtle_observe_plain_at(turtle_observe_stamp t, const char *n,
                                        const void *data, size_t len) {
  emit(t, [&] {
    return Json{
        {"kind", "plain"},
        {"name", str(n)},
        {"length", len},
        {"hex", data && len <= 1048576 ? Json(hex(data, len)) : Json(nullptr)}};
  });
}
extern "C" void turtle_observe_plain(const char *n, const void *data,
                                     size_t len) {
  turtle_observe_plain_at(turtle_observe_now(), n, data, len);
}

namespace turtle::native::detail {
void ready_with_prepared_response() {
  emit(turtle_observe_now(), [] {
    auto ready = event("ready");
    ready["response_source"] = "prepared_environment";
    return ready;
  });
}
uint64_t full_offer(const void *data, size_t length) {
  return emit(turtle_observe_now(), [&] {
    return Json{{"kind", "plain"}, {"name", "write_attempt"},
                {"length", length}, {"hex", hex(data, length)}};
  });
}
void suffix_offer(uint64_t seq, size_t offset, size_t length) {
  emit(turtle_observe_now(), [&] {
    return Json{{"kind", "plain"}, {"name", "write_attempt"},
                {"length", length}, {"offer_ref", seq}, {"suffix_offset", offset}};
  });
}
void read_first_event(turtle_observe_stamp stamp, bool confirmation) {
  emit(stamp, [&] {
    return Json{{"kind", "event"}, {"name", confirmation ? "hs_complete" : "hs_begin"},
                {"message", nullptr}, {"offset", 0}, {"length", 0},
                {confirmation ? "confirmed_by" : "first_operation",
                 confirmation ? "handshake_until_local_complete" : "read_plain"}};
  });
}
} // namespace turtle::native::detail
