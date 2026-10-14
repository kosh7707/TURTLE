#include "turtle/adapter.hpp"
#include <cstdlib>
#include <algorithm>
namespace {
using namespace turtle;
struct MockContext : Context {
    Role role;
    bool mutual;
    MockContext(Role r, bool m) : role(r), mutual(m) {}
};
struct MockConnection : Connection {
    MockContext* context;
    Io io;
    unsigned phase = 0;
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
    d.version = "1";
    d.is_mock = true;
    d.context_description = "Synthetic lifecycle only; no TLS encryption";
    return d;
}
Context* setup(Role role, const TlsConfig& config, const HostServices&,
               std::span<const std::uint8_t> saved) {
    if (!saved.empty())
        return nullptr;
    return new MockContext(role, config.mutual_auth);
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
    return Step::Done;
}
Verification verify(Connection* base) {
    auto& c = *static_cast<MockConnection*>(base);
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
std::vector<std::uint8_t> save(Context*) {
    return {};
}
void teardown(Context* c) noexcept {
    delete c;
}
} // namespace
extern "C" turtle::ImplementationApi turtle_adapter_v1() {
    return {1,          name, declaration, setup, open,  handshake, verify,
            negotiated, send, recv,        error, close, save,      teardown};
}
