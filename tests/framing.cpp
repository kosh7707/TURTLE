#include "frame/framer.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>
using Bytes = std::vector<unsigned char>;
void check(bool value) { if (!value) throw std::runtime_error("raw transport invariant failed"); }
struct Device {
    Bytes bytes;
    std::size_t cursor = 0, chunk = 1;
    bool retry = true;
    static std::ptrdiff_t send(void* opaque, const void* data, std::size_t n) {
        auto& s = *static_cast<Device*>(opaque);
        if (s.retry) { s.retry = false; return TURTLE_WANT_WRITE; }
        n = std::min(n, s.chunk);
        const auto* p = static_cast<const unsigned char*>(data);
        s.bytes.insert(s.bytes.end(), p, p + n);
        return n;
    }
    static std::ptrdiff_t receive(void* opaque, void* data, std::size_t n) {
        auto& s = *static_cast<Device*>(opaque);
        n = std::min({n, s.chunk, s.bytes.size() - s.cursor});
        std::memcpy(data, s.bytes.data() + s.cursor, n);
        s.cursor += n;
        return n;
    }
};
int main() {
    using namespace turtle;
    using namespace turtle::measure;
    const Bytes tls{22,3,3,0,3,1,2,3, 20,3,3,0,1,1, 23,3,3,0,7,1,2,3,4,5,6,7};
    for (std::size_t chunk : {1,2,3,5,8,64}) {
        Device device{{}, 0, chunk};
        Recorder rec(512);
        frame::Stream stream({&device, Device::receive, Device::send}, rec, 0, true);
        auto t = stream.transport();
        const auto call = rec.begin(Kind::call, Operation::handshake);
        // Split headers and coalesced records must not change wire bytes, nor
        // suppress partial successes or convert readiness waits into failures.
        check(t.send(t.state, tls.data(), tls.size()) == TURTLE_WANT_WRITE);
        check(rec.total(Layer::wire, Direction::send) == 0);
        for (std::size_t pos = 0; pos < tls.size();) {
            auto size = tls.size() - pos;
            t.observe(t.state, TURTLE_BIO_BEGIN, 1, nullptr, size, 0);
            auto n = t.send(t.state, tls.data() + pos, size);
            t.observe(t.state, TURTLE_BIO_END, 1, nullptr, size, n);
            check(n > 0);
            const auto& socket = rec.events().back();
            const auto& bio = rec.event(socket.parent);
            check(socket.kind == Kind::socket && bio.kind == Kind::transport);
            check(socket.wire_begin == pos && socket.wire_end == pos + n &&
                  socket.wire_begin == bio.wire_begin && socket.wire_end == bio.wire_end &&
                  bio.call_id == call && bio.transferred == n);
            pos += n;
        }
        check(device.bytes == tls && stream.probe_sent() == tls.size());
        Bytes actual(tls.size());
        for (std::size_t pos = 0; pos < actual.size();) {
            auto n = t.receive(t.state, actual.data() + pos, actual.size() - pos);
            check(n > 0);
            pos += n;
        }
        check(actual == tls && rec.complete());
        auto captured = rec.stream(Layer::wire, Direction::receive);
        check(std::equal(captured.begin(), captured.end(), tls.begin(), tls.end()));
        rec.end(call, true);
    }
    // Diagnostics may be incomplete, but observation overflow must never change
    // a network return value, lose the stream cursor, or splice across a gap.
    Recorder small(1);
    Device device{{}, 0, 128, false};
    frame::Stream stream({&device, Device::receive, Device::send}, small);
    auto t = stream.transport();
    small.begin(Kind::call, Operation::write);
    check(t.send(t.state, tls.data(), tls.size()) == static_cast<ptrdiff_t>(tls.size()));
    check(!small.complete() && small.total(Layer::wire, Direction::send) == tls.size());
    Recorder overflow(4);
    Bytes oversized(Recorder::stream_capacity + 1, 'x');
    overflow.capture(Direction::send, oversized.data(), oversized.size());
    overflow.capture(Direction::send, tls.data(), tls.size());
    check(!overflow.complete() && overflow.stream(Layer::wire, Direction::send).empty() &&
          overflow.total(Layer::wire, Direction::send) == oversized.size() + tls.size());
    for (auto mode : {Mode::off, Mode::basic, Mode::peer}) {
        Recorder silent(16, false, mode);
        frame::Stream raw({&device, Device::receive, Device::send}, silent);
        auto bare = raw.transport();
        check(!bare.observe && bare.send(bare.state, tls.data(), tls.size()) == static_cast<ptrdiff_t>(tls.size()));
        check(silent.events().empty() && silent.stream(Layer::wire, Direction::send).empty());
    }
    std::cout << "raw wire identity, split/coalesced socket and public I/O ranges, readiness, and no-recording paths passed\n";
}
