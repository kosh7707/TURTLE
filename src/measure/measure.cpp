#include "measure/measure.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <limits>
#include <linux/perf_event.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace turtle::measure {
namespace {
std::uint64_t nanoseconds(const timespec& value) noexcept {
    return static_cast<std::uint64_t>(value.tv_sec) * 1000000000ULL + value.tv_nsec;
}
std::uint64_t clock_ns(clockid_t clock) noexcept {
    timespec value{};
    clock_gettime(clock, &value);
    return nanoseconds(value);
}
int open_counter(std::uint64_t config, int group) {
    perf_event_attr attr{};
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = config;
    attr.disabled = group == -1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.read_format =
        PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    return static_cast<int>(
        syscall(SYS_perf_event_open, &attr, 0, -1, group, PERF_FLAG_FD_CLOEXEC));
}
struct alignas(std::max_align_t) Allocation {
    std::size_t size;
};
} // namespace

struct HeapTracker::State {
    explicit State(bool tracking_enabled) : enabled(tracking_enabled) {}

    bool enabled;
    model::HeapSnapshot heap;

    void added(std::size_t size) noexcept {
        heap.live += size;
        heap.allocated_total += size;
        ++heap.allocations;
        heap.peak = std::max(heap.peak, heap.live);
        heap.interval_peak = std::max(heap.interval_peak, heap.live);
    }
    static void* allocate(void* opaque, std::size_t size) noexcept {
        auto& self = *static_cast<State*>(opaque);
        if (!self.enabled)
            return std::malloc(size);
        if (size > std::numeric_limits<std::size_t>::max() - sizeof(Allocation))
            return nullptr;
        auto* block = static_cast<Allocation*>(std::malloc(sizeof(Allocation) + size));
        if (!block)
            return nullptr;
        block->size = size;
        self.added(size);
        return block + 1;
    }
    static void deallocate(void* opaque, void* ptr) noexcept {
        auto& self = *static_cast<State*>(opaque);
        if (!self.enabled) {
            std::free(ptr);
            return;
        }
        if (!ptr)
            return;
        auto* block = static_cast<Allocation*>(ptr) - 1;
        self.heap.live -= block->size;
        ++self.heap.frees;
        std::free(block);
    }
    static void* reallocate(void* opaque, void* ptr, std::size_t size) noexcept {
        auto& self = *static_cast<State*>(opaque);
        if (!self.enabled)
            return std::realloc(ptr, size);
        if (!ptr)
            return allocate(opaque, size);
        if (size == 0) {
            deallocate(opaque, ptr);
            return nullptr;
        }
        if (size > std::numeric_limits<std::size_t>::max() - sizeof(Allocation))
            return nullptr;
        auto* old = static_cast<Allocation*>(ptr) - 1;
        const auto old_size = old->size;
        auto* block = static_cast<Allocation*>(std::realloc(old, sizeof(Allocation) + size));
        if (!block)
            return nullptr;
        block->size = size;
        self.heap.live -= old_size;
        ++self.heap.frees;
        self.added(size);
        return block + 1;
    }
};

HeapTracker::HeapTracker(bool enabled) : state_(std::make_unique<State>(enabled)) {}
HeapTracker::~HeapTracker() = default;
Allocator HeapTracker::allocator() noexcept {
    return {state_.get(), State::allocate, State::reallocate, State::deallocate};
}
std::optional<model::HeapSnapshot> HeapTracker::read(bool reset_interval) noexcept {
    if (!state_->enabled)
        return std::nullopt;
    const auto result = state_->heap;
    if (reset_interval)
        state_->heap.interval_peak = state_->heap.live;
    return result;
}

struct Meter::State {
    explicit State(bool heap_enabled) : heap(heap_enabled) {}

    model::Capabilities capabilities;
    HeapTracker heap;
    int cycles = -1;
    int instructions = -1;

    ~State() {
        if (instructions >= 0)
            ::close(instructions);
        if (cycles >= 0)
            ::close(cycles);
    }
};

Meter::Meter(model::Mode mode, bool request_perf)
    : state_(std::make_unique<State>(mode == model::Mode::Memory)) {
    auto& caps = state_->capabilities;
    timespec resolution{};
    caps.monotonic_clock = clock_getres(CLOCK_MONOTONIC, &resolution) == 0;
    if (caps.monotonic_clock)
        caps.monotonic_resolution_ns = nanoseconds(resolution);
    caps.thread_cpu_clock = clock_getres(CLOCK_THREAD_CPUTIME_ID, &resolution) == 0;
    if (caps.thread_cpu_clock)
        caps.thread_cpu_resolution_ns = nanoseconds(resolution);
    if (!caps.monotonic_clock || !caps.thread_cpu_clock)
        throw std::runtime_error("required measurement clock is unavailable");
    caps.heap_tracking = mode == model::Mode::Memory;
    caps.stack_note = "Unsupported: no verified separate-stack high-water measurement";
    caps.hardware_note = "Hardware timestamps are not configured by the meter";
    caps.trace_note = "No syscall tracing or packet capture configured";
    caps.perf_note = "Disabled by configuration";
    if (!request_perf)
        return;
    state_->cycles = open_counter(PERF_COUNT_HW_CPU_CYCLES, -1);
    if (state_->cycles >= 0)
        state_->instructions = open_counter(PERF_COUNT_HW_INSTRUCTIONS, state_->cycles);
    if (state_->cycles < 0 || state_->instructions < 0 ||
        ioctl(state_->cycles, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) < 0 ||
        ioctl(state_->cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) < 0) {
        caps.perf_note =
            std::string("Per-thread user-space perf group unavailable: ") + std::strerror(errno);
        return;
    }
    caps.perf = true;
    caps.perf_note =
        "Per-thread user-space cycles/instructions; unscaled group counts; check enabled/running";
}

Meter::~Meter() = default;
model::Snapshot Meter::read(bool reset_heap_interval) noexcept {
    model::Snapshot result;
    if (state_->capabilities.perf) {
        struct {
            std::uint64_t count, enabled, running, cycles, instructions;
        } values{};
        if (::read(state_->cycles, &values, sizeof(values)) == sizeof(values) &&
            values.count == 2) {
            result.cycles = values.cycles;
            result.instructions = values.instructions;
            result.perf_enabled = values.enabled;
            result.perf_running = values.running;
        }
    }
    result.thread_cpu_ns = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    result.monotonic_ns = clock_ns(CLOCK_MONOTONIC);
    result.heap = state_->heap.read(reset_heap_interval);
    return result;
}
Allocator Meter::allocator() noexcept {
    return state_->heap.allocator();
}
const model::Capabilities& Meter::capabilities() const noexcept {
    return state_->capabilities;
}
model::Calibration Meter::calibrate(std::size_t repetitions) {
    model::Calibration result;
    result.elapsed_ns.reserve(repetitions);
    result.cpu_ns.reserve(repetitions);
    result.cycles.reserve(repetitions);
    result.instructions.reserve(repetitions);
    for (std::size_t i = 0; i < repetitions; ++i) {
        const auto before = read(false);
        const auto after = read(false);
        result.elapsed_ns.push_back(after.monotonic_ns - before.monotonic_ns);
        result.cpu_ns.push_back(after.thread_cpu_ns - before.thread_cpu_ns);
        if (before.cycles && after.cycles && before.perf_enabled == before.perf_running &&
            after.perf_enabled == after.perf_running) {
            result.cycles.push_back(*after.cycles - *before.cycles);
            result.instructions.push_back(*after.instructions - *before.instructions);
        }
    }
    return result;
}
model::ClockPair clock_pair() noexcept {
    model::ClockPair pair;
    pair.monotonic_before_ns = clock_ns(CLOCK_MONOTONIC);
    pair.realtime_ns = clock_ns(CLOCK_REALTIME);
    pair.monotonic_after_ns = clock_ns(CLOCK_MONOTONIC);
    return pair;
}
} // namespace turtle::measure
