#include "frame/framer.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>
using Bytes = std::vector<unsigned char>;
void check(bool value) { if (!value) throw std::runtime_error("framing invariant failed"); }
struct Device {
    Bytes bytes;
    std::size_t read_offset = 0, chunk = 1;
    static std::ptrdiff_t send(void* opaque, const void* data, std::size_t n) {
        auto& s = *static_cast<Device*>(opaque);
        n = std::min(n, s.chunk);
        const auto* p = static_cast<const unsigned char*>(data);
        s.bytes.insert(s.bytes.end(), p, p + n);
        return static_cast<std::ptrdiff_t>(n);
    }
    static std::ptrdiff_t receive(void* opaque, void* data, std::size_t n) {
        auto& s = *static_cast<Device*>(opaque);
        n = std::min({n, s.chunk, s.bytes.size() - s.read_offset});
        std::memcpy(data, s.bytes.data() + s.read_offset, n);
        s.read_offset += n;
        return static_cast<std::ptrdiff_t>(n);
    }
};
int main() {
    using namespace turtle;
    const Bytes tls{22,3,3,0,3,1,2,3, 20,3,3,0,1,1, 23,3,3,0,7,1,2,3,4,5,6,7};
    const Bytes wire{'T','U',0,1,22,3,3,0,3,1,2,3, 'T','U',0,2,20,3,3,0,1,1,
                     'T','U',0,3,23,3,3,0,7,1,2,3,4,5,6,7};
    for (std::size_t call_chunk : {1,2,3,4,5,7,17,64}) {
        for (std::size_t raw_chunk : {1,2,3,5,17,64}) {
            Device device{{}, 0, raw_chunk};
            measure::Recorder rec;
            frame::Framer send({&device, Device::receive, Device::send}, rec);
            auto tx = send.transport();
            {
                measure::Scope call(rec, measure::Operation::handshake);
                for (std::size_t pos = 0; pos < tls.size();) {
                    const auto n = std::min(call_chunk, tls.size()-pos);
                    check(tx.send(tx.state, tls.data()+pos, n) == static_cast<std::ptrdiff_t>(n));
                    pos += n;
                    // 첫 헤더 한 바이트도 콜백 반환 전에 제출되어야 한다.
                    if (pos == 1) check(device.bytes == Bytes({'T','U',0,1,22}));
                }
                call.succeeded();
            }
            check(device.bytes == wire && send.at_record_boundary() && rec.complete());
            measure::Recorder received;
            frame::Framer receiver({&device, Device::receive, Device::send}, received);
            auto rx = receiver.transport();
            Bytes actual(tls.size());
            {
                measure::Scope call(received, measure::Operation::handshake);
                std::size_t pos = 0;
                while (pos < actual.size()) {
                    const auto n = rx.receive(rx.state, actual.data()+pos, std::min(call_chunk, actual.size()-pos));
                    check(n > 0);
                    pos += static_cast<std::size_t>(n);
                }
                unsigned char last = 0;
                check(rx.receive(rx.state, &last, 1) == 0);
                call.succeeded();
            }
            check(actual == tls && receiver.at_record_boundary() && received.complete());
            check(device.read_offset == wire.size());
            const auto original = received.stream(measure::Layer::tls, measure::Direction::receive);
            check(std::equal(original.begin(), original.end(), tls.begin(), tls.end()));
        }
    }
    frame::Sequence sequence;
    for (unsigned i = 1; i <= 65535; ++i) check(sequence.next() == i);
    check(sequence.next() == 0 && sequence.next() == 0);
    {
        measure::Recorder rec(400000); // 번호 범위 시험은 사건 한도보다 먼저 번호를 소진한다.
        Device device{{}, 0, 64};
        frame::Framer framer({&device, Device::receive, Device::send}, rec);
        const auto tx = framer.transport();
        Bytes many;
        for (unsigned i = 0; i < 65536; ++i) many.insert(many.end(), {20,3,3,0,1,1});
        measure::Scope call(rec, measure::Operation::handshake);
        check(tx.send(tx.state, many.data(), many.size()) == -1);
        check(std::strcmp(rec.reason(), "record_number_exhausted") == 0);
        check(device.bytes.size() == 65535 * 10);
        const auto last = device.bytes.size() - 10;
        check(device.bytes[last+2] == 255 && device.bytes[last+3] == 255);
    }
    std::cout << "incremental framing, partial submission, deframing, sequence exhaustion passed\n";
}
