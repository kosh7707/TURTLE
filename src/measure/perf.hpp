#pragma once
#include <array>
#include <cstdint>

namespace turtle::measure {
enum class PerfAvailability { not_collected, unsupported, available, missing };
const char* name(PerfAvailability) noexcept;
struct PerfSnapshot {
    std::uint64_t cycles = 0, instructions = 0, enabled_ns = 0, running_ns = 0;
    std::uint64_t read_begin_ns = 0, read_end_ns = 0;
    long tid = 0; // thread making this snapshot, not the artifact writer
    bool available = false;
};
class PerfCounters {
public:
    explicit PerfCounters(bool requested) noexcept;
    ~PerfCounters();
    PerfCounters(const PerfCounters&) = delete;
    PerfCounters& operator=(const PerfCounters&) = delete;
    PerfSnapshot snapshot() noexcept;
    long owner_tid() const noexcept { return owner_tid_; }
    bool requested() const noexcept { return requested_; }
    PerfAvailability availability() const noexcept { return availability_; }
    const char* reason() const noexcept { return reason_; }
    int error_number() const noexcept { return error_; }
private:
    void fail(PerfAvailability, const char*, int) noexcept;
    bool requested_;
    long owner_tid_ = 0;
    int leader_ = -1, member_ = -1, error_ = 0;
    std::array<std::uint64_t, 2> ids_{};
    PerfAvailability availability_ = PerfAvailability::not_collected;
    const char* reason_ = nullptr;
};
}
