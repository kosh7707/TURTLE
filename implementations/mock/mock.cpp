#include "turtle/adapter.hpp"
#include <algorithm>
#include <cstdlib>
namespace {
using namespace turtle;
struct MockContext : Context {
    Role role;
    bool mutual;
    std::uint64_t completed = 0;
    MockContext(Role r, bool m, std::uint64_t count) : role(r), mutual(m), completed(count) {}
};
struct MockConnection : Connection {
    MockContext* context;
    Io io;
    unsigned phase = 0;
    bool counted = false;
    std::uint8_t marker = 42;
    MockConnection(MockContext* c, const Io& i) : context(c), io(i) {}
};
Step status(IoResult r) {
    switch (r.status) {
    case IoStatus::Ok:
        return Step::Done;
    case IoStatus::WantRead:
        return Step::WantRead;
    case IoStatus::WantWrite:
        return Step::WantWrite;
    default:
        return Step::Failed;
    }
}
const char* name() noexcept {
    return "mock";
}
Declaration declaration(const Context*) {
    Declaration d;
    d.library = "mock";
    d.version = "2";
    d.is_mock = true;
    d.context_description =
        "Completed synthetic connections as an eight-byte little-endian counter";
    d.context_serialization = true;
    return d;
}
Context* setup(Role role, const TlsConfig& config, const HostServices&,
               std::span<const std::uint8_t> saved) {
    if (!saved.empty() && saved.size() != 8)
        return nullptr;
    std::uint64_t completed = 0;
    for (std::size_t i = 0; i < saved.size(); ++i)
        completed |= static_cast<std::uint64_t>(saved[i]) << (i * 8);
    return new MockContext(role, config.mutual_auth, completed);
}
Connection* open(Context* c, const Io& io) {
    return new MockConnection(static_cast<MockContext*>(c), io);
}
Step handshake(Connection* base) {
    auto& c = *static_cast<MockConnection*>(base);
    while (c.phase < 2) {
        const bool sending = (c.context->role == Role::Client) == (c.phase == 0);
        auto r =
            sending ? c.io.send(c.io.context, &c.marker, 1) : c.io.recv(c.io.context, &c.marker, 1);
        if (r.status != IoStatus::Ok)
            return status(r);
        ++c.phase;
    }
    if (!c.counted) {
        ++c.context->completed;
        c.counted = true;
    }
    return Step::Done;
}
Verification verify(Connection* base) {
    const auto& c = *static_cast<MockConnection*>(base);
    if (std::getenv("TURTLE_MOCK_VERIFY_FAIL"))
        return Verification::Failed;
    return c.context->role == Role::Client || c.context->mutual ? Verification::Passed
                                                                : Verification::NotApplicable;
}
Negotiated negotiated(Connection*) {
    Negotiated n;
    n.version = "mock";
    return n;
}
AppResult send(Connection* base, const std::uint8_t* p, std::size_t n) {
    auto& c = *static_cast<MockConnection*>(base);
    auto r = c.io.send(c.io.context, p, n);
    return {status(r), r.bytes};
}
AppResult recv(Connection* base, std::uint8_t* p, std::size_t n) {
    auto& c = *static_cast<MockConnection*>(base);
    auto r = c.io.recv(c.io.context, p, n);
    return {status(r), r.bytes};
}
const char* error(const Connection*) noexcept {
    return "mock operation failed";
}
void close(Connection* c) noexcept {
    delete c;
}
std::vector<std::uint8_t> save(Context* base) {
    const auto completed = static_cast<MockContext*>(base)->completed;
    std::vector<std::uint8_t> output(8);
    for (std::size_t i = 0; i < output.size(); ++i)
        output[i] = static_cast<std::uint8_t>(completed >> (i * 8));
    return output;
}
void teardown(Context* c) noexcept {
    delete c;
}
} // namespace
extern "C" turtle::ImplementationApi turtle_adapter_v1() {
    return {1,          name, declaration, setup, open,  handshake, verify,
            negotiated, send, recv,        error, close, save,      teardown};
}
