#include "mockca.hpp"
#include "digest/digest.hpp"
#include "socket/socket.hpp"
#include <array>
#include <fstream>
#include <stdexcept>
namespace turtle {
ObjectCache prepare_lookup(const Spec& s, Observer& o) {
    ObjectCache cache;
    if (s.lookup_digest.empty())
        return cache;
    Event total{};
    total.kind = Kind::Lookup;
    total.begin = o.now(false);
    cache.object.resize(s.lookup_size);
    std::vector<std::uint8_t> incoming(s.lookup_size);
    Event e{};
    e.kind = Kind::LookupQuery;
    e.begin = o.now();
    if (!s.lookup_snapshot.empty()) {
        std::ifstream f(s.lookup_snapshot, std::ios::binary);
        f.read(reinterpret_cast<char*>(incoming.data()), std::streamsize(incoming.size()));
        if (std::size_t(f.gcount()) != incoming.size())
            throw std::runtime_error("MockCA snapshot size mismatch");
        e.detail = 1;
    } else {
        auto deadline = monotonic_ns() + std::uint64_t(s.timeout_ms) * 1000000;
        auto socket = connect_socket(s.lookup_address, s.lookup_port, deadline);
        constexpr std::array<std::uint8_t, 16> request = {'T', 'U', 'R', 'T', 'L', 'E', '-', 'M',
                                                          'o', 'c', 'k', 'C', 'A', '/', '1', '\n'};
        write_all(socket.fd(), request, deadline);
        std::array<std::uint8_t, 4> identity_length = {
            std::uint8_t(s.run_id.size() >> 24), std::uint8_t(s.run_id.size() >> 16),
            std::uint8_t(s.run_id.size() >> 8), std::uint8_t(s.run_id.size())};
        write_all(socket.fd(), identity_length, deadline);
        write_all(socket.fd(),
                  {reinterpret_cast<const std::uint8_t*>(s.run_id.data()), s.run_id.size()},
                  deadline);
        std::array<std::uint8_t, 1> role = {std::uint8_t(s.role == TURTLE_CLIENT ? 'C' : 'S')};
        write_all(socket.fd(), role, deadline);
        std::array<std::uint8_t, 8> length{};
        read_all(socket.fd(), length, deadline);
        std::uint64_t count = 0;
        for (auto b : length)
            count = (count << 8) | b;
        if (count != s.lookup_size)
            throw std::runtime_error("MockCA object size mismatch");
        read_all(socket.fd(), incoming, deadline);
    }
    e.end = o.now();
    e.length = incoming.size();
    o.add(e);
    e = {};
    e.kind = Kind::LookupVerify;
    e.begin = o.now();
    if (sha256(incoming) != s.lookup_digest)
        throw std::runtime_error("MockCA object digest mismatch");
    e.end = o.now();
    o.add(e);
    e = {};
    e.kind = Kind::LookupInsert;
    e.begin = o.now();
    std::copy(incoming.begin(), incoming.end(), cache.object.begin());
    e.end = o.now();
    e.length = cache.object.size();
    o.add(e);
    total.end = o.now(false);
    total.length = cache.object.size();
    total.detail = s.lookup_snapshot.empty() ? 0 : 1;
    o.add(total);
    return cache;
}
} // namespace turtle
