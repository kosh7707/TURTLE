#pragma once

#include "measure/perf.hpp"

#include <turtle/implementation.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <ctime>
#include <optional>
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

class Interval;

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
  struct ClientFinished {
    Interval &interval;
    // Only framing is observed here; native TLS still proves which protected
    // record carried the authenticated client Finished.
    std::array<uint64_t, 1024> protected_ends{};
    size_t protected_count = 0;
    std::array<unsigned char, 5> header{};
    size_t header_size = 0, remaining = 0;
    bool protected_record = false;

    uint64_t received_bytes = 0, last_recv_begin = 0, offset = 0;
    size_t proved_row = 0; // one-based; zero means no proof
    measure::CycleSnapshot last_recv_pmu{}, finished_pmu{};
    bool accepting = false, invalid = false;

    explicit ClientFinished(Interval &interval) noexcept : interval(interval) {}
    void observe_records(const unsigned char *bytes, size_t size) noexcept;
    bool is_protected_end(uint64_t end) const noexcept {
      return std::binary_search(protected_ends.begin(),
                                protected_ends.begin() + protected_count, end);
    }
  };

  const long owner_ = syscall(SYS_gettid);
  std::array<Call, 2> pending_{};
  std::array<Row, 16384> rows_{};
  size_t count_ = 0;
  bool covered_ = false, opened_ = false, closed_ = false;
  std::atomic<bool> invalid_{false};
  bool sent_ = false, received_ = false;
  std::optional<ClientFinished> receipt_;

  void invalidate() noexcept { invalid_.store(true, std::memory_order_relaxed); }

  bool on_owner() noexcept {
    if (syscall(SYS_gettid) == owner_)
      return !invalid_.load(std::memory_order_relaxed);
    invalidate();
    return false;
  }

  void received(const unsigned char *bytes, size_t size) noexcept;

  static void client_finished_record(void *context, uint64_t end_offset) noexcept {
    auto &trace = *static_cast<TransportTrace *>(context);
    if (!trace.on_owner() || !trace.receipt_)
      return;
    auto &receipt = *trace.receipt_;
    if (!trace.covered_ || !receipt.accepting || trace.pending_[0].start ||
        receipt.invalid || receipt.offset || !receipt.is_protected_end(end_offset)) {
      receipt.invalid = true;
      return;
    }
    receipt.offset = end_offset;
    // Only the last positive read's counter snapshot is retained. An older
    // matching row can establish wall time but not a cycle interval.
    if (end_offset > receipt.last_recv_begin)
      receipt.finished_pmu = receipt.last_recv_pmu;
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
                  const unsigned char *bytes) noexcept {
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
        if (!sent && result > 0 && trace.receipt_)
          trace.received(bytes, static_cast<size_t>(result));
        call = {};
      }
    }
    errno = saved_errno;
  }

public:
  explicit TransportTrace(Interval *receipt_interval = nullptr) noexcept {
    if (receipt_interval)
      receipt_.emplace(*receipt_interval);
  }

  turtle_transport_hooks hooks() noexcept {
    return {this, coverage, begin, end,
            receipt_ ? client_finished_record : nullptr};
  }
  void accepting_client_finished(bool active) noexcept {
    if (!receipt_)
      return;
    receipt_->accepting = active;
    if (active && receipt_->received_bytes)
      receipt_->invalid = true;
  }
  uint64_t finish_client_finished() noexcept;

  void detached(bool ok) noexcept {
    if (!ok)
      invalidate();
  }
  bool complete() const noexcept {
    return !invalid_.load(std::memory_order_relaxed) && opened_ && closed_ &&
           sent_ && received_;
  }

  void write(std::ostream &out) const {
    out << "direction,start_ns,end_ns,requested,result,cf_record_end\n";
    for (size_t i = 0; i < count_; ++i) {
      const auto &row = rows_[i];
      out << (row.sent ? "send" : "recv") << ',' << row.call.start << ','
          << row.end << ',' << row.call.requested << ',' << row.result << ',';
      if (receipt_ && receipt_->proved_row == i + 1)
        out << receipt_->offset;
      out << '\n';
    }
  }
};

class Interval {
  friend class TransportTrace;
  measure::ThreadCycles counters_;
  measure::CycleSnapshot start_pmu_{}, end_pmu_{};
  uint64_t start_ = 0, end_ = 0;
  const char *event_;
  bool measured_;

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
  Interval(bool measured, const char *event) noexcept
      : counters_(measured), event_(event), measured_(measured) {}

  void start() noexcept {
    if (!measured_)
      return;
    start_pmu_ = counters_.snapshot();
    start_ = monotonic_ns();
  }

  void stop() noexcept {
    if (!measured_)
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
    if (measured_) {
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

inline void TransportTrace::ClientFinished::observe_records(
    const unsigned char *bytes, size_t size) noexcept {
  uint64_t cursor = received_bytes - size;
  constexpr size_t plain_max = 1 << 14, protected_max = plain_max + 256;
  while (size) {
    if (!remaining) {
      while (size && header_size != header.size()) {
        header[header_size++] = *bytes++;
        --size;
        ++cursor;
      }
      if (header_size != header.size())
        return;
      header_size = 0;
      protected_record = header[0] == 23; // TLSCiphertext outer application_data
      remaining = (static_cast<size_t>(header[3]) << 8) | header[4];
      const bool framed = protected_record
          ? header[2] == 3 && remaining >= 9 && remaining <= protected_max
          : header[0] >= 20 && header[0] <= 22 && header[2] >= 1 &&
                header[2] <= 3 && remaining && remaining <= plain_max;
      if (header[1] != 3 || !framed) {
        invalid = true;
        return;
      }
    }
    const auto skip = std::min(remaining, size);
    bytes += skip;
    size -= skip;
    cursor += skip;
    remaining -= skip;
    if (!remaining && protected_record) {
      if (protected_count == protected_ends.size()) {
        invalid = true;
        return;
      }
      protected_ends[protected_count++] = cursor;
    }
  }
}

inline void TransportTrace::received(const unsigned char *bytes, size_t size) noexcept {
  auto &receipt = *receipt_;
  if (size > UINT64_MAX - receipt.received_bytes) {
    receipt.invalid = true;
    return;
  }
  receipt.last_recv_begin = receipt.received_bytes;
  receipt.received_bytes += size;
  if (!receipt.accepting || receipt.invalid || receipt.offset)
    return;
  // The return clock was already captured above. Bracket that same return
  // with the PMU read before doing any record parsing.
  receipt.last_recv_pmu = receipt.interval.counters_.snapshot();
  if (bytes)
    receipt.observe_records(bytes, size);
  else
    receipt.invalid = true;
}

inline uint64_t TransportTrace::finish_client_finished() noexcept {
  if (!complete() || !receipt_ || receipt_->invalid || !receipt_->offset)
    return 0;
  auto &receipt = *receipt_;
  uint64_t received = 0;
  for (size_t i = 0; i < count_; ++i) {
    const auto &row = rows_[i];
    if (row.sent || row.result <= 0)
      continue;
    // The capture-side cumulative was checked for overflow for every read.
    received += static_cast<uint64_t>(row.result);
    if (receipt.offset <= received) {
      auto &interval = receipt.interval;
      if (!interval.start_ || row.end < interval.start_)
        return 0;
      interval.end_ = row.end;
      interval.end_pmu_ = receipt.finished_pmu;
      receipt.proved_row = i + 1;
      return receipt.offset;
    }
  }
  return 0;
}
} // namespace turtle::submission
