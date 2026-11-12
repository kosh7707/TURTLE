#include "measure/measure.hpp"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <thread>

namespace {
std::uint64_t clock_ns(clockid_t clock) {
    timespec t{};
    assert(clock_gettime(clock, &t) == 0);
    return static_cast<std::uint64_t>(t.tv_sec) * 1000000000ULL + t.tv_nsec;
}
turtle::model::Snapshot bracket(turtle::measure::Meter& meter) {
    const auto wall_before = clock_ns(CLOCK_MONOTONIC);
    const auto cpu_before = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    const auto snapshot = meter.read();
    const auto cpu_after = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    const auto wall_after = clock_ns(CLOCK_MONOTONIC);
    assert(wall_before <= snapshot.monotonic_ns && snapshot.monotonic_ns <= wall_after);
    assert(cpu_before <= snapshot.thread_cpu_ns && snapshot.thread_cpu_ns <= cpu_after);
    return snapshot;
}
void print(const char* name, const turtle::model::Snapshot& a, const turtle::model::Snapshot& b) {
    std::cout << name << ": wall_ns=" << b.monotonic_ns - a.monotonic_ns
              << " thread_cpu_ns=" << b.thread_cpu_ns - a.thread_cpu_ns;
    if (a.cycles && b.cycles && a.instructions && b.instructions &&
        a.perf_enabled && b.perf_enabled && a.perf_running && b.perf_running)
        std::cout << " cycles=" << *b.cycles - *a.cycles
                  << " instructions=" << *b.instructions - *a.instructions
                  << " enabled_ns=" << *b.perf_enabled - *a.perf_enabled
                  << " running_ns=" << *b.perf_running - *a.perf_running;
    else
        std::cout << " perf=unobserved";
    std::cout << '\n';
}
} // namespace
int main() {
    turtle::measure::Meter meter(turtle::model::Mode::Memory, true);
    const auto before = bracket(meter);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    const auto slept = bracket(meter);
    assert(slept.monotonic_ns > before.monotonic_ns);
    print("sleep", before, slept);
    // A data-dependent loop kept observable by its final value. No rate or
    // nanosecond-accuracy claim is inferred from these diagnostic readings.
    std::uint64_t value = before.monotonic_ns;
    for (unsigned i = 0; i < 2000000; ++i)
        value = value * 6364136223846793005ULL + 1;
    const auto worked = bracket(meter);
    assert(worked.thread_cpu_ns > slept.thread_cpu_ns);
    print("work", slept, worked);
    std::cout << "observable=" << value << '\n';
    const auto allocator = meter.allocator();
    void* block = allocator.allocate(allocator.context, 100);
    block = allocator.reallocate(allocator.context, block, 7);
    assert(block);
    const auto calibration = meter.calibrate(8);
    assert(calibration.elapsed_ns.size() == 8);
    const auto allocated = bracket(meter);
    assert(allocated.heap->live == 7 && allocated.heap->interval_peak == 100);
    assert(allocated.heap->allocated_total == 107 && allocated.heap->allocations == 2 &&
           allocated.heap->frees == 1);
    allocator.deallocate(allocator.context, block);
    const auto freed = bracket(meter);
    assert(freed.heap->live == 0 && freed.heap->interval_peak == 7);
    assert(bracket(meter).heap->interval_peak == 0);
}
