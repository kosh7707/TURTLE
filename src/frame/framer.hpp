#pragma once
#include "measure/recorder.hpp"
#include <turtle/implementation.h>
#include <array>

namespace turtle::frame {
// 내부 바이트 장치. -2는 EINTR이며 각각의 시도를 따로 기록한다.
struct RawIo {
    void* state;
    std::ptrdiff_t (*receive)(void*, void*, std::size_t);
    std::ptrdiff_t (*send)(void*, const void*, std::size_t);
};
class Sequence {
public:
    unsigned next() noexcept { return value_ <= 65535 ? value_++ : 0; }
private:
    unsigned value_ = 1;
};
class Framer {
public:
    Framer(RawIo io, measure::Recorder& recorder, std::size_t chunk = 0)
        : io_(io), recorder_(recorder), chunk_(chunk) {}
    turtle_transport transport() noexcept;
    bool at_record_boundary() const noexcept;
private:
    struct State {
        Sequence sequence;
        std::array<unsigned char, 5> header{};
        std::size_t header_used = 0, body_left = 0;
        bool active = false;
        void consume(const unsigned char*, std::size_t) noexcept;
        std::size_t limit(std::size_t) const noexcept;
    };
    std::ptrdiff_t send(const void*, std::size_t) noexcept;
    std::ptrdiff_t receive(void*, std::size_t) noexcept;
    std::ptrdiff_t raw(void*, const void*, std::size_t) noexcept;
    bool submit(const unsigned char*, std::size_t, bool tls) noexcept;
    void start(measure::Direction, std::size_t) noexcept;
    std::ptrdiff_t finish(std::ptrdiff_t) noexcept;
    void processing() noexcept;
    RawIo io_;
    measure::Recorder& recorder_;
    std::size_t chunk_;
    State send_, receive_;
    measure::Direction direction_ = measure::Direction::receive;
    std::size_t transport_id_ = 0, processing_id_ = 0;
};
}
