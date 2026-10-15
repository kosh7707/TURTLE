#include "measure/measure.hpp"
#include "measure/perf_internal.hpp"
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <linux/perf_event.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <vector>

namespace {
using turtle::measure::detail::PerfOperations;
using turtle::measure::detail::PerfReadValues;

enum class Failure { None, CyclesOpen, InstructionsOpen, Reset, Enable, InitialRead };

struct FakePerf {
    Failure failure = Failure::None;
    std::vector<perf_event_attr> attributes;
    std::vector<pid_t> pids;
    std::vector<int> cpus;
    std::vector<int> groups;
    std::vector<unsigned long> flags;
    std::vector<int> closed;
    PerfReadValues values{2, 100, 80, 17, 23};

    static int open(void* opaque, const perf_event_attr& attr, pid_t pid, int cpu,
                    int group, unsigned long flags) {
        auto& self = *static_cast<FakePerf*>(opaque);
        self.attributes.push_back(attr);
        self.pids.push_back(pid);
        self.cpus.push_back(cpu);
        self.groups.push_back(group);
        self.flags.push_back(flags);
        if (self.failure == Failure::CyclesOpen && self.attributes.size() == 1) {
            errno = EACCES;
            return -1;
        }
        if (self.failure == Failure::InstructionsOpen && self.attributes.size() == 2) {
            errno = ENOENT;
            return -1;
        }
        return self.attributes.size() == 1 ? 10 : 11;
    }
    static int control(void* opaque, int, unsigned long request, unsigned long) {
        auto& self = *static_cast<FakePerf*>(opaque);
        if (self.failure == Failure::Reset && request == PERF_EVENT_IOC_RESET) {
            errno = EBUSY;
            return -1;
        }
        if (self.failure == Failure::Enable && request == PERF_EVENT_IOC_ENABLE) {
            errno = EPERM;
            return -1;
        }
        return 0;
    }
    static ssize_t read(void* opaque, int, void* output, std::size_t size) {
        auto& self = *static_cast<FakePerf*>(opaque);
        if (self.failure == Failure::InitialRead) {
            errno = EIO;
            return -1;
        }
        assert(size == sizeof(self.values));
        std::memcpy(output, &self.values, size);
        return static_cast<ssize_t>(size);
    }
    static int close(void* opaque, int fd) {
        static_cast<FakePerf*>(opaque)->closed.push_back(fd);
        return 0;
    }
    PerfOperations operations() {
        return {this, open, control, read, close};
    }
};

void assert_failure(Failure failure, turtle::model::PerfFailureStage expected_stage,
                    int expected_errno, std::vector<int> expected_closed) {
    FakePerf fake;
    fake.failure = failure;
    const auto setup = turtle::measure::detail::setup_perf_group(
        turtle::model::PerfScope::UserKernel, fake.operations());
    assert(setup.status == turtle::model::PerfStatus::Unsupported);
    assert(!setup.effective_scope);
    assert(setup.failure_stage == expected_stage);
    assert(setup.error_number == expected_errno);
    assert(setup.cycles_fd == -1 && setup.instructions_fd == -1);
    assert(fake.closed == expected_closed);
}

void test_perf_setup() {
    using namespace turtle;
    FakePerf fake;
    const auto setup = measure::detail::setup_perf_group(model::PerfScope::UserKernel,
                                                         fake.operations());
    assert(setup.status == model::PerfStatus::Available);
    assert(setup.effective_scope == model::PerfScope::UserKernel);
    assert(!setup.failure_stage && !setup.error_number);
    assert(setup.cycles_fd == 10 && setup.instructions_fd == 11);
    assert(fake.pids == std::vector<pid_t>({0, 0}));
    assert(fake.cpus == std::vector<int>({-1, -1}));
    assert(fake.groups == std::vector<int>({-1, 10}));
    assert(fake.flags ==
           std::vector<unsigned long>({PERF_FLAG_FD_CLOEXEC, PERF_FLAG_FD_CLOEXEC}));
    assert(fake.attributes.size() == 2);
    assert(fake.attributes[0].config == PERF_COUNT_HW_CPU_CYCLES);
    assert(fake.attributes[1].config == PERF_COUNT_HW_INSTRUCTIONS);
    assert(fake.attributes[0].disabled == 1 && fake.attributes[1].disabled == 0);
    for (const auto& attr : fake.attributes) {
        assert(attr.inherit == 0);
        assert(attr.exclude_kernel == 0);
        assert(attr.exclude_hv == 1);
        assert(attr.read_format == (PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED |
                                    PERF_FORMAT_TOTAL_TIME_RUNNING));
    }

    const auto user_attr = measure::detail::perf_event_attributes(
        PERF_COUNT_HW_CPU_CYCLES, true, model::PerfScope::User);
    assert(user_attr.exclude_kernel == 1 && user_attr.exclude_hv == 1);
    // setup availability is distinct from event usability: a successful read
    // containing zero time is preserved, not promoted to proof that the PMU ran.
    FakePerf zero_initial;
    zero_initial.values = {2, 0, 0, 0, 0};
    const auto zero_setup = measure::detail::setup_perf_group(
        model::PerfScope::User, zero_initial.operations());
    assert(zero_setup.status == model::PerfStatus::Available);
    assert(zero_setup.effective_scope == model::PerfScope::User);
    fake.values = {2, 0, 0, 0, 0};
    const auto zero = measure::detail::read_perf_group(10, fake.operations());
    assert(zero && zero->enabled == 0 && zero->running == 0);
    fake.values = {2, 100, 40, 31, 37};
    const auto multiplexed = measure::detail::read_perf_group(10, fake.operations());
    assert(multiplexed && multiplexed->running < multiplexed->enabled);
    fake.values.count = 1;
    assert(!measure::detail::read_perf_group(10, fake.operations()));

    assert_failure(Failure::CyclesOpen, model::PerfFailureStage::CyclesOpen, EACCES, {});
    assert_failure(Failure::InstructionsOpen, model::PerfFailureStage::InstructionsOpen,
                   ENOENT, {10});
    assert_failure(Failure::Reset, model::PerfFailureStage::Reset, EBUSY, {11, 10});
    assert_failure(Failure::Enable, model::PerfFailureStage::Enable, EPERM, {11, 10});
    assert_failure(Failure::InitialRead, model::PerfFailureStage::InitialRead, EIO,
                   {11, 10});

    model::Capabilities unsupported;
    unsupported.perf_requested_scope = model::PerfScope::UserKernel;
    unsupported.perf_status = model::PerfStatus::Unsupported;
    unsupported.perf_failure_stage = model::PerfFailureStage::InstructionsOpen;
    unsupported.perf_error_number = ENOENT;
    unsupported.perf_note = "deterministic fixture";
    bool rejected = false;
    try {
        measure::detail::require_perf_scope(unsupported);
    } catch (const std::runtime_error& error) {
        rejected = std::strstr(error.what(), "instructions_open") != nullptr &&
                   std::strstr(error.what(), "errno 2") != nullptr &&
                   std::strstr(error.what(), "deterministic fixture") != nullptr;
    }
    assert(rejected);

    unsupported.perf_status = model::PerfStatus::Available;
    unsupported.perf_effective_scope = model::PerfScope::UserKernel;
    measure::detail::require_perf_scope(unsupported);
    unsupported.perf_effective_scope = model::PerfScope::User;
    rejected = false;
    try {
        measure::detail::require_perf_scope(unsupported);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
    unsupported.perf_requested_scope = model::PerfScope::User;
    unsupported.perf_status = model::PerfStatus::Unsupported;
    unsupported.perf_effective_scope.reset();
    measure::detail::require_perf_scope(unsupported);

    model::Snapshot before;
    model::Snapshot after;
    before.cycles = before.instructions = 0;
    after.cycles = after.instructions = 0;
    before.perf_enabled = before.perf_running = 0;
    after.perf_enabled = after.perf_running = 0;
    assert(!measure::detail::usable_calibration_interval(before, after));
    before.perf_enabled = before.perf_running = 10;
    after.perf_enabled = after.perf_running = 15;
    assert(measure::detail::usable_calibration_interval(before, after));
    after.perf_running = 14;
    assert(!measure::detail::usable_calibration_interval(before, after));
    after.perf_running.reset();
    assert(!measure::detail::usable_calibration_interval(before, after));
}
} // namespace

int main() {
    using namespace turtle;
    measure::Meter timing(model::Mode::Timing, false);
    assert(timing.capabilities().monotonic_clock);
    assert(timing.capabilities().thread_cpu_clock);
    assert(!timing.capabilities().perf);
    assert(timing.capabilities().perf_status == model::PerfStatus::Disabled);
    assert(timing.capabilities().perf_requested_scope == model::PerfScope::User);
    assert(!timing.capabilities().perf_effective_scope);
    timing.require_requested_scope();
    assert(!timing.capabilities().stack_tracking);
    const auto first = timing.read();
    const auto second = timing.read();
    assert(second.monotonic_ns >= first.monotonic_ns);
    assert(second.thread_cpu_ns >= first.thread_cpu_ns);
    assert(!second.heap && !second.cycles && !second.instructions);
    assert(!second.perf_enabled && !second.perf_running);
    const auto calibration = timing.calibrate(32);
    assert(calibration.elapsed_ns.size() == 32);
    assert(calibration.cpu_ns.size() == 32);
    assert(calibration.cycles.empty());
    assert(timing.calibrate(0).elapsed_ns.empty());
    const auto pair = measure::clock_pair();
    assert(pair.monotonic_before_ns <= pair.monotonic_after_ns);
    assert(pair.realtime_ns > 0);

    measure::Meter memory(model::Mode::Memory, false);
    measure::Meter independent(model::Mode::Memory, false);
    const auto allocator = memory.allocator();
    void* block = allocator.allocate(allocator.context, 17);
    assert(block && reinterpret_cast<std::uintptr_t>(block) % alignof(std::max_align_t) == 0);
    std::memset(block, 0x5a, 17);
    auto heap = *memory.read().heap;
    assert(heap.live == 17 && heap.peak == 17 && heap.interval_peak == 17);
    assert(heap.allocations == 1 && heap.frees == 0 && heap.allocated_total == 17);
    assert(independent.read().heap->live == 0);
    block = allocator.reallocate(allocator.context, block, 33);
    assert(block && static_cast<unsigned char*>(block)[16] == 0x5a);
    heap = *memory.read().heap;
    assert(heap.live == 33 && heap.peak == 33 && heap.interval_peak == 33);
    assert(heap.allocations == 2 && heap.frees == 1 && heap.allocated_total == 50);
    void* failed =
        allocator.reallocate(allocator.context, block, std::numeric_limits<std::size_t>::max());
    assert(!failed && memory.read().heap->live == 33);
    block = allocator.reallocate(allocator.context, block, 5);
    assert(block);
    assert(memory.read().heap->interval_peak == 33);
    assert(memory.read().heap->interval_peak == 5);
    allocator.deallocate(allocator.context, block);
    heap = *memory.read().heap;
    assert(heap.live == 0 && heap.peak == 33 && heap.interval_peak == 5);
    assert(memory.read().heap->interval_peak == 0);
    allocator.deallocate(allocator.context, nullptr);
    block = allocator.reallocate(allocator.context, nullptr, 9);
    assert(block);
    assert(allocator.reallocate(allocator.context, block, 0) == nullptr);
    assert(memory.read().heap->live == 0);
    block = allocator.allocate(allocator.context, 0);
    allocator.deallocate(allocator.context, block);
    assert(memory.read().heap->live == 0);
    const auto plain = timing.allocator();
    block = plain.allocate(plain.context, 10);
    block = plain.reallocate(plain.context, block, 20);
    assert(block);
    plain.deallocate(plain.context, block);
    assert(!timing.read().heap);

    measure::HeapTracker tls_heap(true);
    measure::HeapTracker lookup_heap(true);
    const auto tls_allocator = tls_heap.allocator();
    const auto lookup_allocator = lookup_heap.allocator();
    void* tls_block = tls_allocator.allocate(tls_allocator.context, 20);
    void* lookup_block = lookup_allocator.allocate(lookup_allocator.context, 7);
    assert(tls_block && lookup_block);
    tls_block = tls_allocator.reallocate(tls_allocator.context, tls_block, 5);
    assert(tls_block);
    const auto tls_before_lookup_read = *tls_heap.read(false);
    assert(tls_before_lookup_read.live == 5 && tls_before_lookup_read.peak == 20);
    assert(tls_before_lookup_read.interval_peak == 20);
    assert(tls_before_lookup_read.allocations == 2 && tls_before_lookup_read.frees == 1);
    assert(tls_before_lookup_read.allocated_total == 25);
    const auto lookup_snapshot = *lookup_heap.read();
    assert(lookup_snapshot.live == 7 && lookup_snapshot.peak == 7);
    assert(lookup_snapshot.interval_peak == 7);
    assert(lookup_snapshot.allocations == 1 && lookup_snapshot.frees == 0);
    assert(lookup_snapshot.allocated_total == 7);
    assert(tls_heap.read(false)->interval_peak == 20);
    assert(tls_heap.read()->interval_peak == 20);
    assert(tls_heap.read(false)->interval_peak == 5);
    assert(lookup_heap.read(false)->interval_peak == 7);

    measure::Meter tls_meter(model::Mode::Memory, false);
    const auto tls_meter_allocator = tls_meter.allocator();
    void* tls_meter_block = tls_meter_allocator.allocate(tls_meter_allocator.context, 13);
    tls_meter_block =
        tls_meter_allocator.reallocate(tls_meter_allocator.context, tls_meter_block, 3);
    assert(tls_meter_block);
    lookup_heap.read();
    assert(tls_meter.read(false).heap->interval_peak == 13);
    assert(tls_meter.read().heap->interval_peak == 13);
    assert(tls_meter.read(false).heap->interval_peak == 3);
    tls_meter_allocator.deallocate(tls_meter_allocator.context, tls_meter_block);

    tls_allocator.deallocate(tls_allocator.context, tls_block);
    lookup_allocator.deallocate(lookup_allocator.context, lookup_block);
    assert(tls_heap.read()->live == 0);
    assert(lookup_heap.read()->live == 0);

    measure::HeapTracker disabled_heap(false);
    const auto disabled_allocator = disabled_heap.allocator();
    void* disabled_block = disabled_allocator.allocate(disabled_allocator.context, 11);
    disabled_block =
        disabled_allocator.reallocate(disabled_allocator.context, disabled_block, 23);
    assert(disabled_block);
    disabled_allocator.deallocate(disabled_allocator.context, disabled_block);
    assert(!disabled_heap.read());

    measure::Meter perf(model::Mode::Timing, true);
    const auto observed = perf.read();
    if (!perf.capabilities().perf) {
        assert(perf.capabilities().perf_status == model::PerfStatus::Unsupported);
        assert(perf.capabilities().perf_failure_stage);
        assert(perf.capabilities().perf_error_number);
        assert(!observed.cycles);
        assert(!perf.capabilities().perf_note.empty());
    } else if (observed.cycles) {
        assert(perf.capabilities().perf_status == model::PerfStatus::Available);
        assert(perf.capabilities().perf_effective_scope == model::PerfScope::User);
        assert(observed.instructions && observed.perf_enabled && observed.perf_running);
        assert(*observed.perf_running <= *observed.perf_enabled);
    }

    measure::Meter strict_disabled(model::Mode::Timing, false, model::PerfScope::UserKernel);
    assert(strict_disabled.capabilities().perf_status == model::PerfStatus::Disabled);
    assert(strict_disabled.capabilities().perf_requested_scope == model::PerfScope::UserKernel);
    bool rejected = false;
    try {
        strict_disabled.require_requested_scope();
    } catch (const std::runtime_error& error) {
        rejected = std::strstr(error.what(), "user+kernel") != nullptr;
    }
    assert(rejected);

    test_perf_setup();
}
