#include "measure/perf.hpp"
#include "native/endpoint_observe.hpp"
#include "native/evidence.hpp"
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <string>
#include <sys/syscall.h>
#include <turtle/observe.h>
#include <unistd.h>

namespace {
using turtle::artifact::Json;
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
const std::string actor = fd >= 0 ? env("TURTLE_ROLE") : "";
const std::string run_id = fd >= 0 ? env("TURTLE_RUN_ID") : "";
const std::string connection_id = fd >= 0 ? env("TURTLE_CONNECTION_ID") : "";
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
// Fixed storage, no formatting, allocation or evidence I/O while taking
// observations. Overlap is explicit loss instead of a lock wait on the DUT.
enum class Kind { event, fact, identity, coverage, io, bytes, header, plain };
enum class Detail { none, prepared, read_first, read_confirmed, suffix };
struct Payload {
  uint32_t offset = 0, size = 0;
  bool present = false;
};
struct Record {
  turtle_observe_stamp stamp{};
  Kind kind{};
  Detail detail{};
  Payload name{}, data{};
  uint64_t a = 0, b = 0, c = 0;
  int64_t result = 0;
  bool sent = false, peek = false;
};
constexpr size_t payload_limit = 1024 * 1024;
std::array<Record, 8192> records;
std::array<char, 4 * 1024 * 1024> payload;
size_t used = 0, next = 0, flushed = 0;
bool finished = false;
std::atomic_flag recording;
std::atomic<bool> lost;
const pid_t owner = getpid();

struct Access {
  bool held = !recording.test_and_set(std::memory_order_acquire);
  ~Access() {
    if (held)
      recording.clear(std::memory_order_release);
  }
};

Payload copy(const void *data, size_t size, size_t limit) noexcept {
  if (!data)
    return {};
  if (size > limit || size > payload.size() - used) {
    lost.store(true, std::memory_order_relaxed);
    return {};
  }
  Payload result{static_cast<uint32_t>(used), static_cast<uint32_t>(size), true};
  std::memcpy(payload.data() + used, data, size);
  used += size;
  return result;
}

uint64_t record(Record r, const char *name = nullptr, const void *data = nullptr,
                size_t size = 0) noexcept {
  PreserveErrno keep;
  if (fd < 0 || lost.load(std::memory_order_relaxed))
    return 0;
  Access access;
  if (!access.held) {
    lost.store(true, std::memory_order_relaxed);
    return 0;
  }
  if (finished)
    return 0;
  if (next == records.size() || !r.stamp.ns || !r.stamp.tid) {
    lost.store(true, std::memory_order_relaxed);
    return 0;
  }
  if (name)
    r.name = copy(name, strnlen(name, 1025), 1024);
  r.data = copy(data, size, payload_limit);
  if (lost.load(std::memory_order_relaxed))
    return 0;
  records[next++] = r;
  return next; // Sequence is assigned at the call site, not at flush.
}

Json label(Payload p) {
  return p.present ? Json(std::string(payload.data() + p.offset, p.size))
                   : Json(nullptr);
}
Json bytes(Payload p) {
  return p.present ? Json(hex(payload.data() + p.offset, p.size)) : Json(nullptr);
}

Json fields(const Record &r) {
  switch (r.kind) {
  case Kind::event: {
    Json e = {{"kind", "event"}, {"name", label(r.name)}, {"message", nullptr},
              {"offset", 0}, {"length", 0}};
    if (r.detail == Detail::prepared)
      e["response_source"] = "prepared_environment";
    else if (r.detail == Detail::read_first)
      e["first_operation"] = "read_plain";
    else if (r.detail == Detail::read_confirmed)
      e["confirmed_by"] = "handshake_until_local_complete";
    return e;
  }
  case Kind::fact:
    return {{"kind", "fact"}, {"name", label(r.name)},
            {"value", r.result == -1 ? Json(nullptr)
                       : r.result == 0 || r.result == 1 ? Json(bool(r.result))
                                                       : Json(r.result)}};
  case Kind::identity:
    return {{"kind", "identity"}, {"version", r.a}, {"suite", r.b},
            {"group", r.c}, {"peer_name", label(r.name)}};
  case Kind::coverage:
    return {{"kind", "coverage"}, {"source", label(r.name)}, {"active", r.sent}};
  case Kind::io:
    return {{"kind", "io"}, {"begin_ns", r.a}, {"begin_tid", r.b},
            {"source", label(r.name)}, {"requested", r.c}, {"result", r.result},
            {"sent", r.sent}, {"peek", r.peek}, {"hex", bytes(r.data)}};
  case Kind::bytes:
    return {{"kind", "bytes"}, {"source", "stream"}, {"sent", r.sent},
            {"length", r.a}, {"hex", bytes(r.data)}};
  case Kind::header:
    return {{"kind", "header"}, {"sent", r.sent}, {"offset", r.a},
            {"hex", bytes(r.data)}};
  case Kind::plain:
    if (r.detail == Detail::suffix)
      return {{"kind", "plain"}, {"name", label(r.name)}, {"length", r.a},
              {"offer_ref", r.b}, {"suffix_offset", r.c}};
    return {{"kind", "plain"}, {"name", label(r.name)}, {"length", r.a},
            {"hex", bytes(r.data)}};
  }
  return nullptr;
}

Json stream_binding() {
  return {{"v", turtle::native::buffered_evidence_version},
          {"role", actor},
          {"run_id", run_id},
          {"connection_id", connection_id},
          {"pid", owner}};
}

bool publish(const Record &r, size_t seq) {
  const auto &t = r.stamp;
  Json j = stream_binding();
  j.update(Json{{"seq", seq},
                {"tid", t.tid},
                {"ns", t.ns},
                {"pmu", nullptr},
                {"pmu_status", t.pmu_status ? t.pmu_status : "unavailable"},
                {"pmu_reason", t.pmu_reason ? Json(t.pmu_reason) : Json(nullptr)},
                {"pmu_errno", t.pmu_errno}});
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
  j.update(fields(r));
  auto line = j.dump() + "\n";
  return line.size() < 3 * 1024 * 1024 && transmit(line);
}

turtle_observe_stamp clock_stamp() {
  PreserveErrno keep;
  turtle_observe_stamp stamp{};
  stamp.ns = now();
  stamp.tid = uint64_t(syscall(SYS_gettid));
  stamp.pmu_status = "not_collected";
  return stamp;
}

// Touch buffer pages before the application starts, not when recording the
// first measured event on each page. This does not lock or reserve RAM.
void touch_pages(void *storage, size_t size, size_t page) noexcept {
  auto *memory = static_cast<volatile unsigned char *>(storage);
  for (size_t i = 0; i < size; i += page)
    memory[i] = memory[i];
}

struct ExitFlush {
  ExitFlush() {
    if (fd < 0)
      return;
    const auto page = sysconf(_SC_PAGESIZE);
    if (page > 0) {
      touch_pages(records.data(), sizeof(records), page);
      touch_pages(payload.data(), payload.size(), page);
    }
    if (std::atexit(turtle_observe_flush) != 0)
      lost.store(true, std::memory_order_relaxed);
  }
} register_flush;
void flush(bool terminal) noexcept {
  PreserveErrno keep;
  // A forked child must not publish the parent's observations.
  if (fd < 0 || owner != getpid())
    return;
  Access access;
  if (!access.held) {
    lost.store(true, std::memory_order_relaxed);
    return;
  }
  if (finished)
    return;
  finished = terminal;
  try {
    while (flushed < next && publish(records[flushed], flushed + 1))
      ++flushed;
    if (flushed != next)
      lost.store(true, std::memory_order_relaxed);
    if (!lost.load(std::memory_order_relaxed)) {
      if (!terminal || !next)
        return;
      auto seal = stream_binding();
      seal["kind"] = "observer_complete";
      seal["count"] = flushed;
      if (transmit(seal.dump() + "\n"))
        return;
    }
  } catch (...) { // A failed serialization invalidates the whole stream.
  }
  lost.store(true, std::memory_order_relaxed);
  finished = true; // Never retry after a possibly partial frame was written.
  try {
    auto loss = stream_binding();
    loss["kind"] = "observer_loss";
    transmit(loss.dump() + "\n");
  } catch (...) { // Do not change the application exit status.
  }
}
} // namespace

void turtle::native::detail::flush_preparation() { flush(false); }

extern "C" void turtle_observe_flush(void) { flush(true); }

extern "C" turtle_observe_stamp turtle_observe_clock(void) {
  return clock_stamp();
}

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
  record({.stamp = t, .kind = Kind::event}, name);
}
extern "C" void turtle_observe_event(const char *n) {
  turtle_observe_event_at(turtle_observe_now(), n);
}
extern "C" void turtle_observe_fact(const char *n, int v) {
  record({.stamp = clock_stamp(), .kind = Kind::fact, .result = v}, n);
}
extern "C" void turtle_observe_identity(unsigned version, unsigned suite,
                                        unsigned group, const char *peer) {
  record({.stamp = clock_stamp(), .kind = Kind::identity, .a = version,
          .b = suite, .c = group}, peer);
}
extern "C" void turtle_observe_coverage(const char *s, int active) {
  record({.stamp = clock_stamp(), .kind = Kind::coverage, .sent = bool(active)}, s);
}
extern "C" void turtle_observe_io(turtle_observe_stamp b,
                                  turtle_observe_stamp e, const char *s,
                                  int sent, size_t req, int64_t result,
                                  const void *data, int peek) {
  const bool has_bytes = result > 0 && uint64_t(result) <= req &&
                         uint64_t(result) <= payload_limit;
  record({.stamp = e, .kind = Kind::io, .a = b.ns, .b = b.tid, .c = req,
          .result = result, .sent = bool(sent), .peek = bool(peek)},
         s, has_bytes ? data : nullptr,
         has_bytes ? static_cast<size_t>(result) : 0);
}
extern "C" void turtle_observe_bytes(int sent, const void *data, size_t len) {
  record({.stamp = clock_stamp(), .kind = Kind::bytes, .a = len, .sent = bool(sent)},
         nullptr, len <= payload_limit ? data : nullptr, len);
}
extern "C" void turtle_observe_header(int sent, uint64_t offset,
                                      const void *data) {
  record({.stamp = clock_stamp(), .kind = Kind::header, .a = offset, .sent = bool(sent)},
         nullptr, data, 5);
}
extern "C" void turtle_observe_plain_at(turtle_observe_stamp t, const char *n,
                                        const void *data, size_t len) {
  record({.stamp = t, .kind = Kind::plain, .a = len}, n,
         len <= payload_limit ? data : nullptr, len);
}
extern "C" void turtle_observe_plain(const char *n, const void *data,
                                     size_t len) {
  turtle_observe_plain_at(turtle_observe_now(), n, data, len);
}

namespace turtle::native::detail {
void ready_with_prepared_response() {
  record({.stamp = turtle_observe_now(), .kind = Kind::event,
          .detail = Detail::prepared}, "ready");
}
uint64_t full_offer(const void *data, size_t length) {
  return record({.stamp = turtle_observe_now(), .kind = Kind::plain, .a = length},
                "write_attempt", data, length);
}
void suffix_offer(uint64_t seq, size_t offset, size_t length) {
  record({.stamp = turtle_observe_now(), .kind = Kind::plain,
          .detail = Detail::suffix, .a = length, .b = seq, .c = offset},
         "write_attempt");
}
void read_first_event(turtle_observe_stamp stamp, bool confirmation) {
  record({.stamp = stamp, .kind = Kind::event,
          .detail = confirmation ? Detail::read_confirmed : Detail::read_first},
         confirmation ? "hs_complete" : "hs_begin");
}
} // namespace turtle::native::detail
