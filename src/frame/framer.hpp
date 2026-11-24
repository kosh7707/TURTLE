#pragma once
#include "measure/recorder.hpp"
#include <turtle/implementation.h>
#include <turtle/io_boundary.h>

namespace turtle::frame {
// A pass-through socket boundary. Record reconstruction is entirely offline.
constexpr std::ptrdiff_t interrupted = -4; // internal EINTR; retry after recording this syscall
struct RawIo {
    void* state;
    std::ptrdiff_t (*receive)(void*, void*, std::size_t);
    std::ptrdiff_t (*send)(void*, const void*, std::size_t);
};
// One lower call; no entry timestamp can be reconstructed from a positive transfer.
struct SocketObservation {
    size_t event = 0;
    void begin(measure::Recorder &, bool sending, size_t size, size_t parent) noexcept;
    void end(measure::Recorder &, bool sending, const void *, size_t requested, ptrdiff_t raw,
             int error) noexcept;
};
class Stream {
  public:
    Stream(RawIo io, measure::Recorder& recorder, std::size_t chunk = 0, bool probe = false)
        : io_(io), recorder_(recorder), chunk_(chunk), probe_(probe) {}
    turtle_transport transport() noexcept;
    void count_hooks(turtle_io_hooks hooks) noexcept { counts_ = hooks; }
    std::uint64_t probe_sent() const noexcept { return probe_sent_; }
private:
    std::ptrdiff_t transfer(void* out, const void* in, std::size_t size) noexcept;
    void observe(turtle_hook, bool, const void*, std::size_t, std::ptrdiff_t) noexcept;
    RawIo io_;
    turtle_io_hooks counts_{};
    measure::Recorder& recorder_;
    std::size_t chunk_;
    bool probe_;
    std::uint64_t probe_sent_ = 0;
    std::size_t public_call_ = 0;
};
}
