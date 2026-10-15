#include "measure/measure.hpp"
#include "measure/perf_internal.hpp"

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
struct alignas(std::max_align_t) Allocation {
    std::size_t size;
};
} // namespace

namespace detail {
namespace {
int system_open(void*, const perf_event_attr& attr, pid_t pid, int cpu, int group_fd,
                unsigned long flags) {
    return static_cast<int>(
        syscall(SYS_perf_event_open, &attr, pid, cpu, group_fd, flags));
}
int system_control(void*, int fd, unsigned long request, unsigned long argument) {
    return ioctl(fd, request, argument);
}
ssize_t system_read(void*, int fd, void* output, std::size_t size) {
    return ::read(fd, output, size);
}
int system_close(void*, int fd) {
    return ::close(fd);
}

std::optional<PerfReadValues> read_system_perf_group(int cycles_fd) noexcept {
    PerfReadValues values{};
    if (::read(cycles_fd, &values, sizeof(values)) != static_cast<ssize_t>(sizeof(values)) ||
        values.count != 2)
        return std::nullopt;
    return values;
}

PerfSetup failed_setup(PerfSetup setup, model::PerfFailureStage stage, int error_number,
                       const PerfOperations& operations) {
    if (setup.instructions_fd >= 0)
        operations.close(operations.context, setup.instructions_fd);
    if (setup.cycles_fd >= 0)
        operations.close(operations.context, setup.cycles_fd);
    setup.instructions_fd = -1;
    setup.cycles_fd = -1;
    setup.failure_stage = stage;
    setup.error_number = error_number;
    setup.note = std::string("Per-thread perf group unavailable at ") +
                 model::name(stage) + ": " + std::strerror(error_number);
    return setup;
}
} // namespace

perf_event_attr perf_event_attributes(std::uint64_t config, bool leader,
                                      model::PerfScope scope) noexcept {
    perf_event_attr attr{};
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = config;
    attr.disabled = leader;
    attr.inherit = 0;
    attr.exclude_kernel = scope == model::PerfScope::User;
    attr.exclude_hv = 1;
    attr.read_format =
        PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    return attr;
}

std::optional<PerfReadValues> read_perf_group(int cycles_fd,
                                              const PerfOperations& operations) noexcept {
    PerfReadValues values{};
    if (operations.read(operations.context, cycles_fd, &values, sizeof(values)) !=
            static_cast<ssize_t>(sizeof(values)) ||
        values.count != 2)
        return std::nullopt;
    return values;
}

PerfSetup setup_perf_group(model::PerfScope scope, const PerfOperations& operations) {
    PerfSetup setup;
    const auto cycles_attr =
        perf_event_attributes(PERF_COUNT_HW_CPU_CYCLES, true, scope);
    setup.cycles_fd = operations.open(operations.context, cycles_attr, 0, -1, -1,
                                      PERF_FLAG_FD_CLOEXEC);
    if (setup.cycles_fd < 0)
        return failed_setup(std::move(setup), model::PerfFailureStage::CyclesOpen, errno,
                            operations);

    const auto instructions_attr =
        perf_event_attributes(PERF_COUNT_HW_INSTRUCTIONS, false, scope);
    setup.instructions_fd = operations.open(operations.context, instructions_attr, 0, -1,
                                             setup.cycles_fd, PERF_FLAG_FD_CLOEXEC);
    if (setup.instructions_fd < 0)
        return failed_setup(std::move(setup), model::PerfFailureStage::InstructionsOpen,
                            errno, operations);

    if (operations.control(operations.context, setup.cycles_fd, PERF_EVENT_IOC_RESET,
                           PERF_IOC_FLAG_GROUP) < 0)
        return failed_setup(std::move(setup), model::PerfFailureStage::Reset, errno,
                            operations);
    if (operations.control(operations.context, setup.cycles_fd, PERF_EVENT_IOC_ENABLE,
                           PERF_IOC_FLAG_GROUP) < 0)
        return failed_setup(std::move(setup), model::PerfFailureStage::Enable, errno,
                            operations);
    errno = 0;
    if (!read_perf_group(setup.cycles_fd, operations)) {
        const int error_number = errno == 0 ? EIO : errno;
        return failed_setup(std::move(setup), model::PerfFailureStage::InitialRead,
                            error_number, operations);
    }

    setup.status = model::PerfStatus::Available;
    setup.effective_scope = scope;
    setup.note = std::string("Per-thread ") + model::name(scope) +
                 " cycles/instructions; unscaled group counts; check enabled/running";
    return setup;
}

PerfOperations system_perf_operations() noexcept {
    return {nullptr, system_open, system_control, system_read, system_close};
}

void require_perf_scope(const model::Capabilities& caps) {
    if (caps.perf_requested_scope == model::PerfScope::User ||
        (caps.perf_status == model::PerfStatus::Available &&
         caps.perf_effective_scope == model::PerfScope::UserKernel))
        return;
    std::string message = "requested perf scope user+kernel is unavailable";
    if (caps.perf_failure_stage)
        message += std::string(" at ") + model::name(*caps.perf_failure_stage);
    if (caps.perf_error_number)
        message += " (errno " + std::to_string(*caps.perf_error_number) + ")";
    if (!caps.perf_note.empty())
        message += ": " + caps.perf_note;
    throw std::runtime_error(message);
}

bool usable_calibration_interval(const model::Snapshot& before,
                                 const model::Snapshot& after) noexcept {
    if (!before.cycles || !before.instructions || !before.perf_enabled ||
        !before.perf_running || !after.cycles || !after.instructions ||
        !after.perf_enabled || !after.perf_running)
        return false;
    // Equal enabled/running values exclude multiplexed samples. A positive
    // running-time delta proves this interval was actually scheduled; an
    // all-zero setup validation read is availability, not a counter sample.
    return before.perf_enabled == before.perf_running &&
           after.perf_enabled == after.perf_running &&
           *after.perf_running > *before.perf_running;
}
} // namespace detail

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

Meter::Meter(model::Mode mode, bool request_perf, model::PerfScope requested_scope)
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
    caps.perf_requested_scope = requested_scope;
    caps.perf_status = model::PerfStatus::Disabled;
    caps.perf_note = "Disabled by configuration";
    if (!request_perf)
        return;
    auto setup = detail::setup_perf_group(requested_scope, detail::system_perf_operations());
    state_->cycles = setup.cycles_fd;
    state_->instructions = setup.instructions_fd;
    caps.perf_status = setup.status;
    caps.perf_effective_scope = setup.effective_scope;
    caps.perf_failure_stage = setup.failure_stage;
    caps.perf_error_number = setup.error_number;
    caps.perf_note = std::move(setup.note);
    caps.perf = setup.status == model::PerfStatus::Available;
}

Meter::~Meter() = default;
model::Snapshot Meter::read(bool reset_heap_interval) noexcept {
    model::Snapshot result;
    if (state_->capabilities.perf) {
        // Keep the measurement hot path on the direct syscall. The internal
        // operation table is confined to setup validation and component tests.
        if (const auto values = detail::read_system_perf_group(state_->cycles)) {
            result.cycles = values->cycles;
            result.instructions = values->instructions;
            result.perf_enabled = values->enabled;
            result.perf_running = values->running;
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
void Meter::require_requested_scope() const {
    detail::require_perf_scope(state_->capabilities);
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
        if (detail::usable_calibration_interval(before, after)) {
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
