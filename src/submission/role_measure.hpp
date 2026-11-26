#pragma once

#include "measure/perf.hpp"

#include <turtle/implementation.hpp>

#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <ctime>
#include <ostream>
#include <sys/syscall.h>
#include <unistd.h>

namespace turtle::submission {

inline uint64_t monotonic_ns() noexcept {
  timespec ts{};
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return 0;
  return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000 + ts.tv_nsec;
}

class TransportTrace {
  struct Call {
    uint64_t start = 0;
    size_t requested = 0;
  };
  struct Row {
    Call call;
    uint64_t end;
    ptrdiff_t result;
    bool sent;
  };

  const long owner_ = syscall(SYS_gettid);
  std::array<Call, 2> pending_{};
  std::array<Row, 16384> rows_{};
  size_t count_ = 0;
  bool covered_ = false, opened_ = false, closed_ = false;
  std::atomic<bool> invalid_{false};
  bool sent_ = false, received_ = false;

  void invalidate() noexcept { invalid_.store(true, std::memory_order_relaxed); }

  bool on_owner() noexcept {
    if (syscall(SYS_gettid) == owner_)
      return !invalid_.load(std::memory_order_relaxed);
    invalidate();
    return false;
  }

  static void coverage(void *context, int active) noexcept {
    auto &trace = *static_cast<TransportTrace *>(context);
    if (!trace.on_owner())
      return;
    if (active == 1 && !trace.opened_) {
      trace.covered_ = trace.opened_ = true;
    } else if (active == 0 && trace.covered_ &&
               !trace.pending_[0].start && !trace.pending_[1].start) {
      trace.covered_ = false;
      trace.closed_ = true;
    } else {
      trace.invalidate();
    }
  }

  static void begin(void *context, int sent, size_t requested) noexcept {
    auto &trace = *static_cast<TransportTrace *>(context);
    if (!trace.on_owner())
      return;
    auto &call = trace.pending_[sent != 0];
    if (!trace.covered_ || call.start || (sent != 0 && sent != 1))
      trace.invalidate();
    else {
      call = {monotonic_ns(), requested};
      if (!call.start)
        trace.invalidate();
    }
  }

  static void end(void *context, int sent, size_t requested, ptrdiff_t result,
                  const unsigned char *) noexcept {
    const int saved_errno = errno;
    auto &trace = *static_cast<TransportTrace *>(context);
    if (trace.on_owner()) {
      const auto now = monotonic_ns();
      auto &call = trace.pending_[sent != 0];
      if (!trace.covered_ || !call.start || now < call.start ||
          requested != call.requested || (sent != 0 && sent != 1) ||
          (result > 0 && static_cast<size_t>(result) > requested) ||
          trace.count_ == trace.rows_.size()) {
        trace.invalidate();
      } else {
        trace.rows_[trace.count_++] = {call, now, result, sent != 0};
        trace.sent_ |= sent != 0 && result > 0;
        trace.received_ |= sent == 0 && result > 0;
        call = {};
      }
    }
    errno = saved_errno;
  }

public:
  turtle_transport_hooks hooks() noexcept {
    return {this, nullptr, nullptr, coverage, begin, end};
  }
  void detached(bool ok) noexcept {
    if (!ok)
      invalidate();
  }
  bool complete() const noexcept {
    return !invalid_.load(std::memory_order_relaxed) && opened_ && closed_ &&
           sent_ && received_;
  }

  void write(std::ostream &out) const {
    out << "direction,start_ns,end_ns,requested,result\n";
    for (size_t i = 0; i < count_; ++i) {
      const auto &row = rows_[i];
      out << (row.sent ? "send" : "recv") << ',' << row.call.start << ','
          << row.end << ',' << row.call.requested << ',' << row.result << '\n';
    }
  }
};

class Interval {
  measure::ThreadCycles counters_;
  measure::CycleSnapshot start_pmu_{}, end_pmu_{};
  uint64_t start_ = 0, end_ = 0;
  const char *event_;
  bool measured_, has_boundary_;

  bool bracketed() const noexcept {
    // The kernel samples the counter somewhere within each read. Require the
    // whole reads to bracket wall time; do not imply simultaneous endpoints.
    return wall_available() && start_pmu_.read_begin_ns &&
           start_pmu_.read_end_ns <= start_ && end_ <= end_pmu_.read_begin_ns;
  }

  bool have_pmu_delta() const noexcept {
    return bracketed() && start_pmu_.tid > 0 && end_pmu_.tid == start_pmu_.tid &&
           end_pmu_.enabled_ns > start_pmu_.enabled_ns &&
           end_pmu_.running_ns >= start_pmu_.running_ns &&
           end_pmu_.cycles >= start_pmu_.cycles;
  }

public:
  Interval(bool measured, const char *event, bool has_boundary) noexcept
      : counters_(measured && has_boundary), event_(event), measured_(measured),
        has_boundary_(has_boundary) {}

  void start() noexcept {
    if (!measured_)
      return;
    start_pmu_ = counters_.snapshot();
    start_ = monotonic_ns();
  }

  void stop() noexcept {
    if (!measured_ || !has_boundary_)
      return;
    end_ = monotonic_ns();
    end_pmu_ = counters_.snapshot();
  }

  bool wall_available() const noexcept {
    return start_ && end_ && end_ >= start_;
  }

  void write(std::ostream &out) const {
    if (wall_available())
      out << end_ - start_;
    out << ',' << (!measured_ ? "not_collected" : wall_available()
                                                   ? "available" : "unavailable");
    out << ',';
    if (start_)
      out << start_;
    out << ',';
    if (end_)
      out << end_;
    out << ',' << (measured_ ? event_ : "") << ',';
    const bool have_delta = have_pmu_delta();
    const auto enabled = have_delta ? end_pmu_.enabled_ns - start_pmu_.enabled_ns : 0;
    const auto running = have_delta ? end_pmu_.running_ns - start_pmu_.running_ns : 0;
    const bool full_counter = have_delta && enabled == running;
    if (full_counter)
      out << end_pmu_.cycles - start_pmu_.cycles;
    const char *status = "not_collected", *reason = "";
    if (measured_ && !has_boundary_) {
      status = "unavailable";
      reason = "boundary_unobserved";
    } else if (measured_) {
      if (!wall_available()) {
        status = "unavailable";
        reason = "boundary_unobserved";
      } else if (counters_.status() != measure::CycleStatus::available) {
        status = measure::name(counters_.status());
        reason = counters_.reason();
      } else if (!bracketed()) {
        status = "unavailable";
        reason = "counter_reads_do_not_bracket_wall";
      } else if (!have_delta) {
        status = "unavailable";
        reason = "counter_delta_unobserved";
      } else if (!full_counter) {
        status = "unavailable";
        reason = "counter_not_continuously_scheduled";
      } else {
        status = "available";
      }
    }
    out << ',' << status << ',' << reason << ',';
    if (have_delta)
      out << enabled;
    out << ',';
    if (have_delta)
      out << running;
  }
};
} // namespace turtle::submission
