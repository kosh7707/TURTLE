#include "measure/perf.hpp"
#ifndef TURTLE_NO_PMU
#include <cerrno>
#include <ctime>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace turtle::measure {
namespace {
bool clock_ns(std::uint64_t& value) noexcept {
    timespec t{};
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return false;
    value = static_cast<std::uint64_t>(t.tv_sec) * 1000000000ULL + t.tv_nsec;
    return true;
}
}
} // namespace turtle::measure
#endif
namespace turtle::measure {
const char* name(PerfAvailability value) noexcept {
    switch (value) {
    case PerfAvailability::not_collected: return "not_collected";
    case PerfAvailability::unsupported: return "unsupported";
    case PerfAvailability::available: return "available";
    case PerfAvailability::missing: return "missing";
    case PerfAvailability::partial: return "partial";
    }
    return "missing";
}
#ifndef TURTLE_NO_PMU
void PerfCounters::fail(PerfAvailability status, const char* reason, int error) noexcept {
    availability_ = status;
    reason_ = reason;
    error_ = error;
}
PerfCounters::PerfCounters(bool requested, bool allow_cycles_only) noexcept : requested_(requested) {
    if (!requested) return;
    owner_tid_ = syscall(SYS_gettid);
    perf_event_attr attr{};
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID |
                       PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    leader_ = static_cast<int>(syscall(SYS_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC));
    if (leader_ < 0) { fail(PerfAvailability::unsupported, "cycles_open_failed", errno); return; }
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    member_ = static_cast<int>(syscall(SYS_perf_event_open, &attr, 0, -1, leader_, PERF_FLAG_FD_CLOEXEC));
    if (member_ < 0) {
        fail(allow_cycles_only ? PerfAvailability::partial : PerfAvailability::unsupported, "instructions_open_failed", errno);
        if (!allow_cycles_only) return;
    }
    if (ioctl(leader_, PERF_EVENT_IOC_ID, &ids_[0]) != 0 || (member_ >= 0 && ioctl(member_, PERF_EVENT_IOC_ID, &ids_[1]) != 0) ||
        ioctl(leader_, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0 ||
        ioctl(leader_, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
        fail(PerfAvailability::unsupported, "group_setup_failed", errno); return;
    }
    if (member_ >= 0) availability_ = PerfAvailability::available;
}
PerfCounters::~PerfCounters() {
    if (member_ >= 0) close(member_);
    if (leader_ >= 0) close(leader_);
}
PerfSnapshot PerfCounters::snapshot() noexcept {
    PerfSnapshot out;
    if (!requested_) return out;
    out.tid = syscall(SYS_gettid);
    if (availability_ != PerfAvailability::available && availability_ != PerfAvailability::partial) return out;
    if (out.tid != owner_tid_) { fail(PerfAvailability::missing, "counter_thread_mismatch", 0); return out; }
    std::array<std::uint64_t, 7> data{};
    if (!clock_ns(out.read_begin_ns)) { fail(PerfAvailability::missing, "counter_read_clock_failed", errno); return out; }
    ssize_t bytes;
    do { bytes = read(leader_, data.data(), sizeof(data)); } while (bytes < 0 && errno == EINTR);
    const int error = bytes < 0 ? errno : 0;
    if (!clock_ns(out.read_end_ns)) { fail(PerfAvailability::missing, "counter_read_clock_failed", errno); return out; }
    const std::size_t members = member_ >= 0 ? 2 : 1, words = 3 + 2 * members;
    if (bytes != static_cast<ssize_t>(words * sizeof(data[0])) || data[0] != members || data[2] > data[1]) {
        fail(PerfAvailability::missing, "counter_group_read_failed", error); return out;
    }
    bool cycles = false, instructions = false;
    for (std::size_t i = 3; i < words; i += 2) {
        if (data[i + 1] == ids_[0] && !cycles) { out.cycles = data[i]; cycles = true; }
        else if (member_ >= 0 && data[i + 1] == ids_[1] && !instructions) { out.instructions = data[i]; instructions = true; }
        else { fail(PerfAvailability::missing, "counter_group_id_mismatch", 0); return out; }
    }
    out.enabled_ns = data[1];
    out.running_ns = data[2];
    out.available = cycles && instructions;
    return out;
}
#else
PerfCounters::PerfCounters(bool requested, bool) noexcept : requested_(requested) {
    if (requested) { availability_ = PerfAvailability::unsupported; reason_ = "pmu_not_built"; }
}
PerfCounters::~PerfCounters() = default;
PerfSnapshot PerfCounters::snapshot() noexcept { return {}; }
#endif
}
