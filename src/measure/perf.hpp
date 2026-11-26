#pragma once

#include <cstdint>

namespace turtle::measure {
enum class CycleStatus { not_collected, unsupported, available, missing };
const char *name(CycleStatus status) noexcept;

struct CycleSnapshot {
  std::uint64_t cycles = 0, enabled_ns = 0, running_ns = 0;
  std::uint64_t read_begin_ns = 0, read_end_ns = 0;
  long tid = 0;
};

class ThreadCycles {
public:
  explicit ThreadCycles(bool requested) noexcept;
  ~ThreadCycles();
  ThreadCycles(const ThreadCycles &) = delete;
  ThreadCycles &operator=(const ThreadCycles &) = delete;

  CycleSnapshot snapshot() noexcept;
  CycleStatus status() const noexcept { return status_; }
  const char *reason() const noexcept { return reason_; }

private:
  long owner_tid_ = 0;
  int fd_ = -1;
  CycleStatus status_ = CycleStatus::not_collected;
  const char *reason_ = "";

  void unavailable(CycleStatus status, const char *reason) noexcept;
};
} // namespace turtle::measure
