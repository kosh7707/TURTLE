#include "frame/framer.hpp"
#include <algorithm>
#include <cstring>
namespace turtle::frame {
using namespace measure;
void Framer::State::consume(const unsigned char* data, std::size_t size) noexcept {
    if (header_used < 5) {
        std::memcpy(header.data() + header_used, data, size);
        header_used += size;
        if (header_used == 5) body_left = (static_cast<unsigned>(header[3]) << 8) | header[4];
    } else {
        body_left -= size;
    }
    if (header_used == 5 && body_left == 0) { active = false; header_used = 0; }
}
std::size_t Framer::State::limit(std::size_t size) const noexcept {
    return std::min(size, header_used < 5 ? 5 - header_used : body_left);
}
turtle_transport Framer::transport() noexcept {
    return {this,
        [](void* s, void* b, std::size_t n) { return static_cast<Framer*>(s)->receive(b, n); },
        [](void* s, const void* b, std::size_t n) { return static_cast<Framer*>(s)->send(b, n); }};
}
void Framer::processing() noexcept {
    processing_id_ = recorder_.begin(Kind::frame, Operation::none, direction_, transport_id_);
}
void Framer::start(Direction direction, std::size_t size) noexcept {
    direction_ = direction;
    transport_id_ = recorder_.begin(Kind::transport, Operation::none, direction,
                                    recorder_.active_call(), size);
    processing();
    const auto call = recorder_.active_call();
    if (!call || recorder_.event(call).operation == Operation::prepare)
        recorder_.fail("transport_outside_scenario_or_shutdown");
}
std::ptrdiff_t Framer::finish(std::ptrdiff_t n) noexcept {
    recorder_.end(processing_id_, recorder_.complete());
    recorder_.end(transport_id_, n >= 0 && recorder_.complete(), n);
    return recorder_.complete() ? n : -1;
}
std::ptrdiff_t Framer::raw(void* out, const void* in, std::size_t size) noexcept {
    if (!recorder_.complete()) return -1;
    if (chunk_) size = std::min(size, chunk_);
    std::ptrdiff_t n;
    do {
        recorder_.end(processing_id_, true);
        const auto id = recorder_.begin(Kind::socket, Operation::none, direction_, transport_id_, size);
        n = direction_ == Direction::send ? io_.send(io_.state, in, size) : io_.receive(io_.state, out, size);
        recorder_.end(id, n >= 0, n);
        processing();
    } while (n == -2 && recorder_.complete());
    if (n < 0 || static_cast<std::size_t>(n) > size) {
        recorder_.fail("socket_io_failed");
        return -1;
    }
    if (n > 0) recorder_.capture(Layer::wire, direction_, in ? in : out, static_cast<std::size_t>(n));
    return n;
}
bool Framer::submit(const unsigned char* data, std::size_t size, bool tls) noexcept {
    while (size && recorder_.complete()) {
        const auto n = raw(nullptr, data, size);
        if (n <= 0) { recorder_.fail("socket_write_no_progress"); return false; }
        const auto count = static_cast<std::size_t>(n);
        if (tls) {
            recorder_.capture(Layer::tls, Direction::send, data, count);
            send_.consume(data, count);
        }
        data += count;
        size -= count;
    }
    return recorder_.complete();
}
std::ptrdiff_t Framer::send(const void* buffer, std::size_t size) noexcept {
    start(Direction::send, size);
    const auto* data = static_cast<const unsigned char*>(buffer);
    const auto requested = size;
    while (size && recorder_.complete()) {
        if (!send_.active) {
            const auto number = send_.sequence.next();
            if (!number) { recorder_.fail("record_number_exhausted"); break; }
            const unsigned char prefix[]{'T', 'U', static_cast<unsigned char>(number >> 8),
                                         static_cast<unsigned char>(number & 255)};
            if (!submit(prefix, sizeof(prefix), false)) break;
            send_.active = true;
        }
        const auto count = send_.limit(size);
        if (!submit(data, count, true)) break;
        data += count;
        size -= count;
    }
    return finish(static_cast<std::ptrdiff_t>(requested - size));
}
std::ptrdiff_t Framer::receive(void* buffer, std::size_t size) noexcept {
    start(Direction::receive, size);
    if (!size) return finish(0);
    if (!receive_.active) {
        std::array<unsigned char, 4> prefix{};
        std::size_t used = 0;
        while (used < prefix.size() && recorder_.complete()) {
            const auto n = raw(prefix.data() + used, nullptr, prefix.size() - used);
            if (n <= 0) {
                if (used || n < 0) recorder_.fail("incomplete_frame_prefix");
                return finish(n);
            }
            used += static_cast<std::size_t>(n);
        }
        const auto number = receive_.sequence.next();
        if (!number) recorder_.fail("record_number_exhausted");
        else if (prefix[0] != 'T' || prefix[1] != 'U' ||
                 ((static_cast<unsigned>(prefix[2]) << 8) | prefix[3]) != number)
            recorder_.fail("frame_sequence_mismatch");
        receive_.active = true;
    }
    const auto n = raw(buffer, nullptr, receive_.limit(size));
    if (n > 0) {
        const auto count = static_cast<std::size_t>(n);
        recorder_.capture(Layer::tls, Direction::receive, buffer, count);
        receive_.consume(static_cast<const unsigned char*>(buffer), count);
    } else {
        recorder_.fail("incomplete_tls_record");
    }
    return finish(n);
}
bool Framer::at_record_boundary() const noexcept { return !send_.active && !receive_.active; }
}
