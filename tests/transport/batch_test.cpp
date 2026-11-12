#include "transport/channel.hpp"
#include <cassert>
#include <cstdint>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

struct Evidence {
    std::size_t accepted = 0, submitted = 0, writes = 0;
    std::uint64_t batch = 0;
    bool consistent = true;
};
int main() {
    int sockets[2];
    assert(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) == 0);
    int small = 1024;
    assert(::setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
    std::vector<std::uint8_t> storage(256 * 1024), payload(storage.size()),
        received(payload.size());
    for (std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<std::uint8_t>(i % 251);
    Evidence evidence;
    turtle::transport::Channel channel{
        sockets[0], &evidence, [](void* p, const turtle::transport::Observation& event) noexcept {
            auto& e = *static_cast<Evidence*>(p);
            if (event.entering)
                return;
            if (!e.batch)
                e.batch = event.batch_id;
            e.consistent &= event.batch_id == e.batch;
            if (event.buffered)
                e.accepted += event.result.bytes;
            else {
                e.submitted += event.result.bytes;
                ++e.writes;
            }
        }};
    channel.output = storage;
    channel.holding = true;
    auto io = channel.io();
    const auto one = io.send(io.context, payload.data(), 123);
    const auto two = io.send(io.context, payload.data() + 123, payload.size() - 123);
    assert(one.bytes == 123 && two.bytes == payload.size() - 123);
    assert(evidence.accepted == payload.size() && evidence.submitted == 0);
    std::uint8_t unused = 0;
    assert(::recv(sockets[1], &unused, 1, 0) == -1);
    channel.holding = false;
    auto first = channel.flush();
    assert(first.bytes > 0 && first.bytes < payload.size());
    const auto blocked = channel.flush();
    assert(blocked.status == turtle::IoStatus::WantWrite);
    std::size_t offset = 0;
    for (unsigned iteration = 0; offset < received.size() && iteration < 100000; ++iteration) {
        const auto n = ::recv(sockets[1], received.data() + offset, received.size() - offset, 0);
        if (n > 0)
            offset += static_cast<std::size_t>(n);
        if (channel.queued) {
            const auto result = channel.flush();
            assert(result.status == turtle::IoStatus::Ok ||
                   result.status == turtle::IoStatus::WantWrite);
        }
    }
    assert(offset == received.size() && received == payload);
    assert(channel.queued == 0 && evidence.submitted == payload.size());
    assert(evidence.consistent && evidence.batch != 0 && evidence.writes > 2);
    ::close(sockets[0]);
    ::close(sockets[1]);
}
