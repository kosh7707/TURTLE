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
std::size_t index(Layer layer, Direction direction) noexcept {
    return static_cast<std::size_t>(layer) * 2 + static_cast<std::size_t>(direction);
}
}
Stamp now() noexcept {
    Stamp result;
    result.wall_available = read_clock(CLOCK_MONOTONIC, result.wall_ns);
    result.cpu_available = read_clock(CLOCK_THREAD_CPUTIME_ID, result.cpu_ns);
    return result;
}
Recorder::Recorder(std::size_t capacity, bool perf) : counters_(perf) {
    for (auto& stream : streams_) stream.data.resize(stream_capacity);
    events_.resize(capacity); // 측정 전에 실제 메모리를 만진다.
    events_.clear();
}
Stamp Recorder::stamp() noexcept {
    auto result = now();
    result.perf = counters_.snapshot();
    return result;
}
std::size_t Recorder::begin(Kind kind, Operation op, Direction direction,
                            std::size_t parent, std::size_t requested) noexcept {
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
    if (!events_.back().begin.wall_available || !events_.back().begin.cpu_available) fail("clock_unavailable");
    return event.id;
}
void Recorder::end(std::size_t id, bool success, std::ptrdiff_t transferred) noexcept {
    const auto stopped = stamp();
    if (!id) return;
    auto& event = events_[id - 1];
    event.success = success;
    event.transferred = transferred;
    event.tls_end = total(Layer::tls, event.direction);
    event.wire_end = total(Layer::wire, event.direction);
    if (event.kind == Kind::socket && transferred > 0)
        event.wire_end = event.wire_begin + static_cast<std::uint64_t>(transferred);
    event.end = stopped;
    if (!event.end.wall_available || !event.end.cpu_available) fail("clock_unavailable");
    if (event.kind == Kind::call) active_call_ = 0;
}
void Recorder::capture(Layer layer, Direction direction, const void* data, std::size_t size) noexcept {
    auto& stream = streams_[index(layer, direction)];
    if (size > stream.data.size() - stream.size) { fail("stream_capacity"); return; }
    if (size) std::memcpy(stream.data.data() + stream.size, data, size);
    stream.size += size;
}
std::span<const unsigned char> Recorder::stream(Layer layer, Direction direction) const noexcept {
    const auto& stream = streams_[index(layer, direction)];
    return {stream.data.data(), stream.size};
}
std::uint64_t Recorder::total(Layer layer, Direction direction) const noexcept {
    return streams_[index(layer, direction)].size;
}
}
