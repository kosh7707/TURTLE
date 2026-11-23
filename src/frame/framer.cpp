#include "frame/framer.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
namespace turtle::frame {
using namespace measure;
turtle_transport Stream::transport() noexcept {
    turtle_transport out{};
    out.state = this;
    out.receive = [](void* s, void* b, std::size_t n) { return static_cast<Stream*>(s)->transfer(b, nullptr, n); };
    out.send = [](void* s, const void* b, std::size_t n) { return static_cast<Stream*>(s)->transfer(nullptr, b, n); };
    if (recorder_.detailed())
        out.observe = [](void* s, turtle_hook k, int tx, const void* data, std::size_t n, std::ptrdiff_t done) {
            const int saved = errno;
            static_cast<Stream*>(s)->observe(k, tx != 0, data, n, done);
            errno = saved;
        };
    return out;
}
std::ptrdiff_t Stream::transfer(void* out, const void* in, std::size_t size) noexcept {
    const auto dir = in ? Direction::send : Direction::receive;
    if (chunk_) size = std::min(size, chunk_);
    for (;;) {
        const auto id = recorder_.detailed() ? recorder_.begin(Kind::socket, Operation::none, dir,
                             public_call_ ? public_call_ : recorder_.active_call(), size) : 0;
        const auto n = in ? io_.send(io_.state, in, size) : io_.receive(io_.state, out, size);
        const auto saved = errno;
        if (recorder_.detailed()) {
            recorder_.end(id, n >= 0, n >= 0 ? n : -1);
            if (id) {
                auto& e = recorder_.event(id);
                e.source = in ? "send" : "recv";
                e.error_number = n < 0 ? saved : 0;
            }
            if (n > 0 && static_cast<std::size_t>(n) <= size) recorder_.capture(dir, in ? in : out, n);
        }
        if (probe_ && in && n > 0) probe_sent_ += n;
        errno = saved;
        if (n != interrupted) return n;
    }
}
void Stream::observe(turtle_hook kind, bool tx, const void* data, std::size_t n, std::ptrdiff_t done) noexcept {
    const auto dir = tx ? Direction::send : Direction::receive;
    if (kind == TURTLE_BIO_BEGIN || kind == TURTLE_IO_BEGIN) {
        if (public_call_) { recorder_.fail("nested_adapter_io"); return; }
        public_call_ = recorder_.begin(Kind::transport, Operation::none, dir, recorder_.active_call(), n);
        if (public_call_) recorder_.event(public_call_).source = kind == TURTLE_BIO_BEGIN ? "openssl_bio" : "adapter_io";
    } else if (kind == TURTLE_BIO_END || kind == TURTLE_IO_END) {
        if (!public_call_) { recorder_.fail("unpaired_adapter_io"); return; }
        recorder_.end(public_call_, done >= 0, done);
        public_call_ = 0;
    } else if (kind == TURTLE_RECORD_HEADER || kind == TURTLE_HANDSHAKE_MESSAGE) {
        const bool header = kind == TURTLE_RECORD_HEADER;
        if (!data || (header ? n != 5 : !n)) { recorder_.fail("invalid_adapter_notification"); return; }
        const auto id = recorder_.begin(header ? Kind::header : Kind::message, Operation::none, dir, recorder_.active_call(), n);
        if (!id) return;
        auto& e = recorder_.event(id);
        e.source = header ? "record_header" : "handshake_message";
        if (header) std::memcpy(e.header.data(), data, 5);
        else e.message_type = *static_cast<const unsigned char*>(data);
        recorder_.end(id, true);
    }
}
}
