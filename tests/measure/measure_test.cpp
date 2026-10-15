#include "measure/measure.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>

int main() {
    using namespace turtle;
    measure::Meter timing(model::Mode::Timing, false);
    assert(timing.capabilities().monotonic_clock);
    assert(timing.capabilities().thread_cpu_clock);
    assert(!timing.capabilities().perf);
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
        assert(!observed.cycles);
        assert(!perf.capabilities().perf_note.empty());
    } else if (observed.cycles) {
        assert(observed.instructions && observed.perf_enabled && observed.perf_running);
        assert(*observed.perf_running <= *observed.perf_enabled);
    }
}
