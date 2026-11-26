#include "measure/perf.hpp"

#ifndef TURTLE_NO_PMU
#include <cerrno>
#include <ctime>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace turtle::measure {
const char *name(CycleStatus status) noexcept {
  switch (status) {
  case CycleStatus::not_collected:
    return "not_collected";
  case CycleStatus::unsupported:
    return "unsupported";
  case CycleStatus::available:
    return "available";
  case CycleStatus::missing:
    return "missing";
  }
  return "missing";
}

void ThreadCycles::unavailable(CycleStatus status, const char *reason) noexcept {
  status_ = status;
  reason_ = reason;
}

#ifndef TURTLE_NO_PMU
namespace {
std::uint64_t clock_ns() noexcept {
  timespec t{};
  if (clock_gettime(CLOCK_MONOTONIC, &t) != 0)
    return 0;
  return static_cast<std::uint64_t>(t.tv_sec) * 1'000'000'000 + t.tv_nsec;
}
} // namespace

ThreadCycles::ThreadCycles(bool requested) noexcept {
  if (!requested)
    return;

  owner_tid_ = syscall(SYS_gettid);
  if (owner_tid_ <= 0) {
    unavailable(CycleStatus::unsupported, "counter_thread_unknown");
    return;
  }

  perf_event_attr attr{};
  attr.size = sizeof(attr);
  attr.type = PERF_TYPE_HARDWARE;
  attr.config = PERF_COUNT_HW_CPU_CYCLES;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
  // pid=0 follows the calling thread across CPUs; inherit is disabled.
  fd_ = static_cast<int>(syscall(SYS_perf_event_open, &attr, 0, -1, -1,
                                 PERF_FLAG_FD_CLOEXEC));
  if (fd_ < 0) {
    unavailable(CycleStatus::unsupported,
                errno == EACCES || errno == EPERM ? "cycles_open_denied"
                                                 : "cycles_open_failed");
    return;
  }
  status_ = CycleStatus::available;
}

ThreadCycles::~ThreadCycles() {
  if (fd_ >= 0)
    close(fd_);
}

CycleSnapshot ThreadCycles::snapshot() noexcept {
  if (status_ != CycleStatus::available)
    return {};

  CycleSnapshot out;
  out.tid = syscall(SYS_gettid);
  if (out.tid != owner_tid_) {
    unavailable(CycleStatus::missing, "counter_thread_mismatch");
    return {};
  }

  std::uint64_t data[3]{};
  out.read_begin_ns = clock_ns();
  ssize_t bytes;
  do {
    bytes = read(fd_, data, sizeof(data));
  } while (bytes < 0 && errno == EINTR);
  out.read_end_ns = clock_ns();

  if (!out.read_begin_ns || out.read_end_ns < out.read_begin_ns) {
    unavailable(CycleStatus::missing, "counter_read_clock_failed");
    return {};
  }
  if (bytes != sizeof(data) || data[2] > data[1]) {
    unavailable(CycleStatus::missing, "cycles_read_failed");
    return {};
  }
  out.cycles = data[0];
  out.enabled_ns = data[1];
  out.running_ns = data[2];
  return out;
}
#else
ThreadCycles::ThreadCycles(bool requested) noexcept {
  if (requested)
    unavailable(CycleStatus::unsupported, "pmu_not_built");
}
ThreadCycles::~ThreadCycles() = default;
CycleSnapshot ThreadCycles::snapshot() noexcept { return {}; }
#endif
} // namespace turtle::measure
