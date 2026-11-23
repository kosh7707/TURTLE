#pragma once
#include "measure/perf.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace turtle::measure {
enum class Mode { peer, off, basic, detailed };
enum class Kind { call, transport, socket, header, message };
enum class Operation { prepare, handshake, read, write, server_first, verify, shutdown, none };
enum class Direction { receive, send };
enum class Layer { tls, wire };
struct Stamp {
    std::uint64_t wall_ns = 0, cpu_ns = 0;
    bool wall_available = false, cpu_available = false;
    PerfSnapshot perf;
};
Stamp now() noexcept;
struct Event {
    std::size_t id = 0, parent = 0, call_id = 0;
    Kind kind = Kind::call;
    Operation operation = Operation::none;
    Direction direction = Direction::receive;
    std::size_t requested = 0;
    std::ptrdiff_t transferred = 0;
    std::uint64_t tls_begin = 0, tls_end = 0, wire_begin = 0, wire_end = 0;
    std::uint64_t plaintext_begin = 0, plaintext_end = 0;
    const char* source = nullptr;
    std::array<unsigned char, 5> header{};
    int message_type = -1, error_number = 0;
    Stamp begin, end;
    bool success = false;
};
class Recorder {
public:
    static constexpr std::size_t stream_capacity = 2 * 1024 * 1024;
    static constexpr std::size_t event_capacity = 65536;
    explicit Recorder(std::size_t capacity = event_capacity, bool perf = false, Mode mode = Mode::detailed);
    Stamp stamp() noexcept;
    const PerfCounters& counters() const noexcept { return counters_; }
    Mode mode() const noexcept { return mode_; }
    bool calls() const noexcept { return mode_ == Mode::basic || mode_ == Mode::detailed; }
    bool detailed() const noexcept { return mode_ == Mode::detailed; }
    std::size_t begin(Kind, Operation = Operation::none, Direction = Direction::receive,
                      std::size_t parent = 0, std::size_t requested = 0) noexcept;
    Stamp end(std::size_t, bool success, std::ptrdiff_t transferred = 0) noexcept;
    void capture(Direction, const void*, std::size_t) noexcept;
    std::span<const unsigned char> stream(Layer, Direction) const noexcept;
    std::uint64_t total(Layer, Direction) const noexcept;
    const std::vector<Event>& events() const noexcept { return events_; }
    Event& event(std::size_t id) { return events_.at(id - 1); }
    std::size_t active_call() const noexcept { return active_call_; }
    void fail(const char* reason) noexcept { if (!reason_) reason_ = reason; }
    const char* reason() const noexcept { return reason_; }
    bool complete() const noexcept { return reason_ == nullptr; }
private:
    PerfCounters counters_;
    Mode mode_;
    struct Stream { std::vector<unsigned char> data; std::uint64_t total = 0; std::size_t stored = 0; };
    std::array<Stream, 2> streams_;
    std::vector<Event> events_;
    std::size_t active_call_ = 0;
    const char* reason_ = nullptr;
};
}
