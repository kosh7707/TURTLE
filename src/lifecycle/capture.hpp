#pragma once

// The role runtime owns this capture state. Meter is the only compile-time
// seam so tests can inspect the fixed record buffer exactly when read() runs;
// production uses measure::Meter and no virtual or function-pointer clock.
#include "record/record.hpp"
#include "transport/channel.hpp"
#include "turtle/adapter.hpp"

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace turtle::lifecycle::detail {

template <class Meter> struct Capture {
    Meter& meter;
    record::Buffer& buffer;
    std::size_t connection = 0;
    std::uint64_t sequence = 0, call_id = 0, sent = 0, received = 0;
    model::Call call = model::Call::None;
    std::uint64_t first_receive = 0;
    bool heap_supported = false;

    model::Snapshot snapshot() noexcept {
        auto value = meter.read();
        if (!heap_supported)
            value.heap.reset();
        return value;
    }

    void event(model::EventKind kind, model::Location location = model::Location::Boundary,
               std::int64_t result = 0, std::size_t requested = 0,
               std::size_t transferred = 0, int system_error = 0) noexcept {
        model::Event recorded;
        recorded.kind = kind;
        recorded.location = location;
        recorded.result = result;
        recorded.requested = requested;
        recorded.transferred = transferred;
        recorded.system_error = system_error;
        recorded.connection = connection;
        recorded.sequence = ++sequence;
        recorded.call = call;
        recorded.call_id = call_id;
        recorded.snapshot = snapshot();
        buffer.append(recorded);
    }

    static void observe(void* context, const transport::Observation& observation) noexcept {
        auto& capture = *static_cast<Capture*>(context);
        model::Event recorded;
        recorded.connection = capture.connection;
        recorded.sequence = ++capture.sequence;
        recorded.call = capture.call;
        recorded.call_id = capture.call_id;
        recorded.batch_id = observation.batch_id;
        if (observation.buffered) {
            recorded.kind = model::EventKind::OutputAccepted;
            recorded.location = model::Location::Framework;
            recorded.transferred = observation.result.bytes;
            recorded.snapshot = capture.snapshot();
            capture.buffer.append(recorded);
            return;
        }
        if (observation.entering)
            recorded.snapshot = capture.snapshot();
        recorded.kind = observation.sending
                            ? (observation.entering ? model::EventKind::IoSendEnter
                                                    : model::EventKind::IoSendReturn)
                            : (observation.entering ? model::EventKind::IoRecvEnter
                                                    : model::EventKind::IoRecvReturn);
        auto& offset = observation.sending ? capture.sent : capture.received;
        recorded.stream_begin = offset;
        recorded.requested = observation.requested;

        if (observation.entering) {
            recorded.stream_end = offset;
            capture.buffer.append(recorded);
            return;
        }

        recorded.transferred = observation.result.bytes;
        recorded.result = static_cast<int>(observation.result.status);
        recorded.system_error = observation.result.system_error;
        offset += observation.result.bytes;
        recorded.stream_end = offset;

        auto* return_event = capture.buffer.prepare_event(recorded);
        model::Event* kernel_event = nullptr;
        if (observation.result.bytes) {
            capture.buffer.append_bytes(capture.connection,
                                        observation.sending ? model::Direction::Sent
                                                            : model::Direction::Received,
                                        {observation.data, observation.result.bytes});
            if (!observation.sending && !capture.first_receive)
                capture.first_receive = recorded.sequence;
            if (observation.kernel_realtime_ns) {
                recorded.kind = model::EventKind::KernelRx;
                recorded.location = model::Location::Kernel;
                recorded.sequence = ++capture.sequence;
                recorded.raw_timestamp_ns = observation.kernel_realtime_ns;
                kernel_event = capture.buffer.prepare_event(recorded);
            }
        }

        // Stream copying and both fixed event-slot reservations are framework
        // I/O work. Capture them before this single composite meter read so
        // they are not charged to the following library computation segment.
        const auto return_snapshot = capture.snapshot();
        if (return_event)
            return_event->snapshot = return_snapshot;
        if (kernel_event)
            kernel_event->snapshot = return_snapshot;
    }

    static void observe_tx(void* context, const transport::TxObservation& source) noexcept {
        auto& capture = *static_cast<Capture*>(context);
        model::Event event;
        event.kind = source.kind;
        event.location = model::Location::Kernel;
        event.connection = capture.connection;
        event.sequence = ++capture.sequence;
        event.raw_timestamp_ns = source.realtime_ns;
        event.timestamp_id = source.byte_id;
        event.stream_end = static_cast<std::uint64_t>(source.byte_id) + 1;
        // A request's last byte is known; the timestamp does not describe an
        // exact full packet/record byte range. ACK is cumulative, ignoring SACK.
        event.timestamp_coverage_exact = false;
        event.snapshot = capture.snapshot(); // userspace collection time
        capture.buffer.append(event);
    }

    static bool trace(void* context, const TraceEvent& source) noexcept {
        auto& capture = *static_cast<Capture*>(context);
        model::Event event;
        event.kind = source.phase == TracePhase::Begin ? model::EventKind::InternalBegin
                                                       : model::EventKind::InternalEnd;
        event.location = model::Location::Library;
        event.connection = capture.connection;
        event.sequence = ++capture.sequence;
        event.call = capture.call;
        event.call_id = capture.call_id;
        event.trace_operation = source.operation;
        event.message_id = source.message_id;
        event.message_type = source.message_type;
        event.result = source.result;
        event.snapshot = capture.snapshot();
        return capture.buffer.append(event);
    }

    template <class Function>
    auto invoke(model::Call operation, Function&& function, std::size_t requested = 0) {
        call = operation;
        ++call_id;
        event(model::EventKind::CallBegin, model::Location::Boundary, 0, requested);
        auto result = function();
        std::int64_t code = 0;
        std::size_t transferred = 0;
        int system_error = 0;
        if constexpr (std::is_same_v<decltype(result), AppResult>) {
            code = static_cast<int>(result.step);
            transferred = result.bytes;
        } else if constexpr (std::is_same_v<decltype(result), IoResult>) {
            code = static_cast<int>(result.status);
            transferred = result.bytes;
            system_error = result.system_error;
        } else if constexpr (std::is_enum_v<decltype(result)>) {
            code = static_cast<int>(result);
        }
        event(model::EventKind::CallEnd, model::Location::Boundary, code, requested, transferred,
              system_error);
        return result;
    }
};

} // namespace turtle::lifecycle::detail
