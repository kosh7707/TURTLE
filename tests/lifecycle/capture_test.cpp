#include "lifecycle/capture.hpp"

#include <array>
#include <cassert>
#include <cerrno>
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

struct SequenceMeter {
    std::uint64_t tick = 0;
    turtle::model::Snapshot read() noexcept {
        turtle::model::Snapshot result;
        result.monotonic_ns = ++tick;
        result.thread_cpu_ns = tick;
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

    // Two partial successful submissions around a retry contribute 2+0+1
    // bytes. Buffer acceptance itself is not a socket submission.
    turtle::record::Buffer partial_buffer({16, 3, 0, 1});
    SequenceMeter partial_meter;
    turtle::lifecycle::detail::Capture<SequenceMeter> partial{partial_meter, partial_buffer};
    auto observation = returned;
    observation.sending = true;
    observation.kernel_realtime_ns = 0;
    observation.buffered = true;
    decltype(partial)::observe(&partial, observation);
    assert(partial.sent == 0 && partial_buffer.bytes(0, Direction::Sent).empty());
    observation.buffered = false;
    for (const auto count : {2U, 0U, 1U}) {
        observation.data = bytes.data() + partial.sent;
        observation.requested = bytes.size() - partial.sent;
        observation.entering = true;
        decltype(partial)::observe(&partial, observation);
        observation.entering = false;
        observation.result = {count ? IoStatus::Ok : IoStatus::WantWrite, count, 0};
        decltype(partial)::observe(&partial, observation);
    }
    assert(partial.sent == 3 && partial.received == 0 && partial.first_receive == 0);
    const auto stream = partial_buffer.bytes(0, Direction::Sent);
    assert(stream.size() == 3 && stream[0] == 7 && stream[1] == 8 && stream[2] == 9);
    assert(partial_buffer.events()[4].transferred == 0);
    assert(partial_buffer.events()[4].stream_begin == 2 && partial_buffer.events()[4].stream_end == 2);

    // A buffered flush returns IoResult rather than AppResult. Preserve its
    // partial submission and ordinary nonblocking retry in the call boundary.
    turtle::record::Buffer flush_buffer({6, 0, 0, 1});
    SequenceMeter flush_meter;
    turtle::lifecycle::detail::Capture<SequenceMeter> flush{flush_meter, flush_buffer};
    const std::array<turtle::IoResult, 3> outcomes{{
        {IoStatus::Ok, 2, 0}, {IoStatus::WantWrite, 0, EAGAIN}, {IoStatus::Ok, 1, 0}}};
    std::size_t remaining = 3;
    for (std::size_t i = 0; i < outcomes.size(); ++i) {
        const auto expected = outcomes[i];
        const auto actual = flush.invoke(turtle::model::Call::Flush,
                                         [expected] { return expected; }, remaining);
        const auto begin = flush_buffer.events()[2 * i];
        const auto end = flush_buffer.events()[2 * i + 1];
        assert(actual.status == expected.status && actual.bytes == expected.bytes);
        assert(begin.requested == remaining && end.requested == remaining);
        assert(end.call == turtle::model::Call::Flush && end.kind == EventKind::CallEnd);
        assert(end.result == static_cast<int>(expected.status));
        assert(end.transferred == expected.bytes && end.system_error == expected.system_error);
        assert(end.call_id == begin.call_id && end.snapshot.monotonic_ns > begin.snapshot.monotonic_ns);
        remaining -= actual.bytes;
    }
    assert(remaining == 0);
}
