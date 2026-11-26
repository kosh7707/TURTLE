#include "measure/recorder.hpp"
#include <cstring>
#include <ctime>
namespace turtle::measure {
namespace {
bool read_clock(clockid_t clock, std::uint64_t& value) noexcept {
    timespec time{};
    if (clock_gettime(clock, &time) != 0) return false;
    value = static_cast<std::uint64_t>(time.tv_sec) * 1000000000ULL + time.tv_nsec;
    return true;
}
}
Stamp now() noexcept {
    Stamp result;
    result.wall_available = read_clock(CLOCK_MONOTONIC, result.wall_ns);
    result.cpu_available = read_clock(CLOCK_THREAD_CPUTIME_ID, result.cpu_ns);
    return result;
}
Recorder::Recorder(std::size_t capacity, bool perf, Mode mode) : counters_(perf && mode != Mode::peer), mode_(mode) {
    if (!calls()) return;
    if (detailed()) for (auto& stream : streams_) stream.data.resize(stream_capacity);
    events_.resize(capacity); // Touch the event buffer before measurement starts.
    events_.clear();
}
Stamp Recorder::stamp() noexcept {
    if (mode_ == Mode::peer) return {};
    auto result = now();
    result.perf = counters_.snapshot();
    return result;
}
std::size_t Recorder::begin(Kind kind, Operation op, Direction direction,
                            std::size_t parent, std::size_t requested) noexcept {
    if (!calls() || (kind != Kind::call && !detailed())) return 0;
    if (events_.size() == events_.capacity()) { fail("event_capacity"); return 0; }
    if (kind == Kind::call && active_call_) { fail("nested_call"); return 0; }
    Event event;
    event.id = events_.size() + 1;
    event.kind = kind;
    event.operation = op;
    event.direction = direction;
    event.parent = parent;
    event.requested = requested;
    if (kind == Kind::call) active_call_ = event.id;
    event.call_id = active_call_;
    event.tls_begin = total(Layer::tls, direction);
    event.wire_begin = total(Layer::wire, direction);
    events_.push_back(event);
    events_.back().begin = stamp();
    if (!events_.back().begin.wall_available) fail("clock_unavailable");
    return event.id;
}
Stamp Recorder::end(std::size_t id, bool success, std::ptrdiff_t transferred) noexcept {
    const auto stopped = stamp();
    if (!id) return stopped;
    auto& event = events_[id - 1];
    event.success = success;
    event.transferred = transferred;
    event.tls_end = total(Layer::tls, event.direction);
    event.wire_end = total(Layer::wire, event.direction);
    if (event.kind == Kind::socket && transferred > 0)
        event.tls_end = event.wire_end = event.wire_begin + static_cast<std::uint64_t>(transferred);
    event.end = stopped;
    if (!event.end.wall_available) fail("clock_unavailable");
    if (event.kind == Kind::call) active_call_ = 0;
    return stopped;
}
void Recorder::capture(Direction direction, const void* data, std::size_t size) noexcept {
    auto& stream = streams_[static_cast<unsigned>(direction)];
    stream.total += size;
    if (size > stream.data.size() - stream.stored) { fail("stream_capacity"); return; }
    if (stream.stored != stream.total - size) return; // never splice across a gap
    if (size) std::memcpy(stream.data.data() + stream.stored, data, size);
    stream.stored += size;
}
std::span<const unsigned char> Recorder::stream(Layer, Direction direction) const noexcept {
    const auto& s = streams_[static_cast<unsigned>(direction)];
    return {s.data.data(), s.stored};
}
std::uint64_t Recorder::total(Layer, Direction direction) const noexcept {
    return streams_[static_cast<unsigned>(direction)].total;
}
}
