#pragma once
#include "measure/recorder.hpp"
#include <turtle/implementation.h>

namespace turtle::frame {
// A pass-through socket boundary. Record reconstruction is entirely offline.
constexpr std::ptrdiff_t interrupted = -4; // internal EINTR; retry after recording this syscall
struct RawIo {
    void* state;
    std::ptrdiff_t (*receive)(void*, void*, std::size_t);
    std::ptrdiff_t (*send)(void*, const void*, std::size_t);
};
class Stream {
public:
    Stream(RawIo io, measure::Recorder& recorder, std::size_t chunk = 0, bool probe = false)
        : io_(io), recorder_(recorder), chunk_(chunk), probe_(probe) {}
    turtle_transport transport() noexcept;
    std::uint64_t probe_sent() const noexcept { return probe_sent_; }
private:
    std::ptrdiff_t transfer(void* out, const void* in, std::size_t size) noexcept;
    void observe(turtle_hook, bool, const void*, std::size_t, std::ptrdiff_t) noexcept;
    RawIo io_;
    measure::Recorder& recorder_;
    std::size_t chunk_;
    bool probe_;
    std::uint64_t probe_sent_ = 0;
    std::size_t public_call_ = 0;
};
}
