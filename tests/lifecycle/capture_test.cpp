#include "lifecycle/capture.hpp"

#include <array>
#include <cassert>
#include <cstdint>

namespace {

struct FakeMeter {
    turtle::record::Buffer& buffer;
    std::size_t expected_events = 0;
    std::size_t expected_bytes = 0;
    std::size_t reads = 0;

    turtle::model::Snapshot read() noexcept {
        ++reads;
        assert(buffer.events().size() == expected_events);
        assert(buffer.bytes(3, turtle::model::Direction::Received).size() == expected_bytes);
        turtle::model::Snapshot result;
        result.monotonic_ns = 101;
        result.thread_cpu_ns = 202;
        result.cycles = 303;
        result.instructions = 304;
        result.perf_enabled = 305;
        result.perf_running = 306;
        turtle::model::HeapSnapshot heap;
        heap.live = 307;
        result.heap = heap;
        return result;
    }
};

} // namespace

int main() {
    using turtle::model::Direction;
    using turtle::model::EventKind;
    using turtle::IoStatus;

    const std::array<std::uint8_t, 3> bytes{7, 8, 9};
    turtle::record::Buffer buffer({4, 3, 0, 4});
    FakeMeter meter{buffer, 2, bytes.size()};
    turtle::lifecycle::detail::Capture<FakeMeter> capture{meter, buffer};
    capture.heap_supported = true;
    capture.connection = 3;
    capture.call = turtle::model::Call::Handshake;
    capture.call_id = 11;

    turtle::transport::Observation returned{};
    returned.sending = false;
    returned.entering = false;
    returned.data = bytes.data();
    returned.requested = 9;
    returned.result = {IoStatus::Ok, bytes.size(), 0};
    returned.kernel_realtime_ns = 404;
    decltype(capture)::observe(&capture, returned);

    assert(meter.reads == 1);
    assert(capture.first_receive == 1);
    assert(capture.received == bytes.size());
    assert(buffer.bytes(3, Direction::Received).size() == bytes.size());
    const auto events = buffer.events();
    assert(events.size() == 2);
    assert(events[0].kind == EventKind::IoRecvReturn && events[0].sequence == 1);
    assert(events[0].connection == 3 && events[0].call_id == 11);
    assert(events[0].stream_begin == 0 && events[0].stream_end == bytes.size());
    assert(events[0].requested == 9 && events[0].transferred == bytes.size());
    assert(events[0].snapshot.monotonic_ns == 101);
    assert(events[1].kind == EventKind::KernelRx && events[1].sequence == 2);
    assert(events[1].location == turtle::model::Location::Kernel);
    assert(events[1].raw_timestamp_ns == 404);
    assert(events[1].snapshot.monotonic_ns == events[0].snapshot.monotonic_ns);
    assert(events[1].snapshot.thread_cpu_ns == events[0].snapshot.thread_cpu_ns);
    assert(events[1].snapshot.cycles == events[0].snapshot.cycles);
    assert(events[1].snapshot.instructions == events[0].snapshot.instructions);
    assert(events[1].snapshot.perf_enabled == events[0].snapshot.perf_enabled);
    assert(events[1].snapshot.perf_running == events[0].snapshot.perf_running);
    assert(events[0].snapshot.heap && events[1].snapshot.heap);
    assert(events[0].snapshot.heap->live == 307 && events[1].snapshot.heap->live == 307);

    // ENTER keeps its existing boundary: the snapshot precedes event storage.
    turtle::record::Buffer enter_buffer({1, 0, 0, 1});
    FakeMeter enter_meter{enter_buffer, 0, 0};
    turtle::lifecycle::detail::Capture<FakeMeter> enter_capture{enter_meter, enter_buffer};
    turtle::transport::Observation entering{};
    entering.sending = true;
    entering.entering = true;
    entering.requested = 5;
    decltype(enter_capture)::observe(&enter_capture, entering);
    assert(enter_meter.reads == 1);
    assert(enter_buffer.events().size() == 1);
    assert(enter_buffer.events()[0].kind == EventKind::IoSendEnter);

    // Capacity failures remain explicit even when a prepared RETURN survives.
    turtle::record::Buffer short_buffer({1, 2, 0, 4});
    FakeMeter short_meter{short_buffer, 1, 0};
    turtle::lifecycle::detail::Capture<FakeMeter> short_capture{short_meter, short_buffer};
    short_capture.connection = 3;
    decltype(short_capture)::observe(&short_capture, returned);
    assert(short_meter.reads == 1);
    assert(short_buffer.events().size() == 1);
    assert(short_buffer.events()[0].snapshot.monotonic_ns == 101);
    assert(short_buffer.overflowed() && short_buffer.dropped() == 2);
}
