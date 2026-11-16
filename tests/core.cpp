#include "allocation/allocation.hpp"
#include "digest/digest.hpp"
#include "execution/execution.hpp"
#include <algorithm>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

static void require(bool ok, const char* text) {
    if (!ok)
        throw std::runtime_error(text);
}
struct turtle_context {};
struct turtle_connection {
    unsigned selected = 0, tx = 0, rx = 0, builds = 0, parses = 0, protects = 0, opens = 0;
    std::size_t received = 0, assembled = 0;
    bool assembling = false, processing = false;
};
static std::size_t message_size(unsigned type) {
    return type == 11 ? 12001 : type == 15 ? 80 : 40;
}
static int transition(turtle_connection* c, turtle_transition op, unsigned type,
                      turtle_bytes data) {
    switch (op) {
    case TURTLE_PREPARE_SEND:
        require(!c->assembling, "assembly overlap");
        c->assembling = true;
        c->selected = type;
        c->assembled = 0;
        break;
    case TURTLE_COMMIT_SEND:
        require(c->assembling && c->assembled == data.size, "commit before assembly done");
        c->assembling = false;
        if (type == 2)
            c->tx = 1;
        if (type == 20)
            c->tx = 2;
        break;
    case TURTLE_PREPARE_RECEIVE:
        require(!c->processing, "processing overlap");
        c->processing = true;
        c->received = 0;
        c->selected = type;
        break;
    case TURTLE_COMMIT_RECEIVE:
        require(!c->processing && c->received == data.size, "commit before parsing");
        if (type == 2)
            c->rx = 1;
        if (type == 20)
            c->rx = 2;
        break;
    default:
        break;
    }
    // ServerHello changes both handshake directions.
    if (type == 2 && (op == TURTLE_COMMIT_RECEIVE || op == TURTLE_COMMIT_SEND))
        c->tx = c->rx = 1;
    return 1;
}
static turtle_progress assemble(turtle_connection* c, unsigned type, std::size_t offset,
                                turtle_buffer out) {
    require(c->assembling && c->selected == type && offset == c->assembled, "assembly ordering");
    if (!offset)
        ++c->builds;
    auto total = message_size(type), n = std::min({total - offset, out.size, std::size_t(853)});
    for (std::size_t i = 0; i < n; ++i) {
        auto j = offset + i;
        auto body = total - 4;
        out.data[i] = j == 0   ? type
                      : j == 1 ? (body >> 16)
                      : j == 2 ? (body >> 8)
                      : j == 3 ? body
                               : (j * 7) & 255;
    }
    c->assembled += n;
    return {offset + n == total ? TURTLE_DONE : TURTLE_MORE, 0, n, 0};
}
static turtle_progress process(turtle_connection* c, unsigned type, turtle_bytes in, int last) {
    require(c->processing && c->selected == type, "processing ordering");
    auto consumed = std::min(in.size, std::size_t(257));
    c->received += consumed;
    bool complete = last && consumed == in.size;
    if (complete) {
        require(c->received == message_size(type), "fragment reconstruction");
        c->processing = false;
        ++c->parses;
    }
    return {complete ? TURTLE_DONE : TURTLE_MORE, consumed, 0, 0};
}
static turtle_progress protect(turtle_connection* c, unsigned type, turtle_bytes in,
                               turtle_buffer out) {
    ++c->protects;
    require(out.size >= in.size + 7, "toy record capacity");
    out.data[0] = c->tx ? 23 : type;
    out.data[1] = out.data[2] = 3;
    out.data[3] = (in.size + 2) >> 8;
    out.data[4] = (in.size + 2) & 255;
    out.data[5] = type;
    out.data[6] = c->tx;
    for (std::size_t i = 0; i < in.size; ++i)
        out.data[i + 7] = in.data[i] ^ c->tx;
    return {TURTLE_DONE, in.size, in.size + 7, 0};
}
static turtle_progress unprotect(turtle_connection* c, turtle_bytes in, turtle_buffer out,
                                 unsigned* type) {
    ++c->opens;
    require(in.size >= 7 && out.size >= in.size - 7 && in.data[6] == c->rx,
            "record key transition");
    *type = in.data[5];
    for (std::size_t i = 7; i < in.size; ++i)
        out.data[i - 7] = in.data[i] ^ c->rx;
    return {TURTLE_DONE, in.size, in.size - 7, 0};
}
static turtle_result result(const turtle_connection*) {
    turtle_result r{};
    r.full_handshake = r.peer_verified = r.peer_certificate = 1;
    return r;
}
static const char* error(const turtle_connection*) {
    return "toy implementation";
}
static void exercise(turtle::Scenario scenario, bool bundle, bool hello) {
    using namespace turtle;
    int fd[2];
    require(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0, "socketpair");
    turtle_implementation api{};
    api.transition = transition;
    api.assemble = assemble;
    api.process = process;
    api.protect = protect;
    api.unprotect = unprotect;
    api.result = result;
    api.error = error;
    Spec c;
    c.white = true;
    c.stream = true;
    c.mutual = true;
    c.scenario = scenario;
    c.bundle = bundle;
    c.hello_first = hello;
    c.record_size = 997;
    c.io_chunk = 73;
    c.client_bytes = 19003;
    c.server_bytes = 20117;
    c.timeout_ms = 3000;
    Spec s = c;
    s.role = TURTLE_SERVER;
    Observer co(true, false, true, 40000), so(true, false, true, 40000);
    turtle_connection ct{}, st{};
    Execution ce(c, api, &ct, co, fd[0], 1), se(s, api, &st, so, fd[1], 1);
    std::exception_ptr failure;
    std::thread server([&] {
        try {
            se.run();
        } catch (...) {
            failure = std::current_exception();
        }
    });
    try {
        ce.run();
    } catch (...) {
        shutdown(fd[0], SHUT_RDWR);
        server.join();
        close(fd[0]);
        close(fd[1]);
        throw;
    }
    server.join();
    close(fd[0]);
    close(fd[1]);
    if (failure)
        std::rethrow_exception(failure);
    require(ct.builds == 4 && ct.parses == 6 && st.builds == 6 && st.parses == 4,
            "logical functions run once");
    require(ce.tx_stream == se.rx_stream && se.tx_stream == ce.rx_stream,
            "partial I/O changed protected bytes");
    for (auto* observer : {&co, &so}) {
        auto records = std::count_if(observer->events.begin(), observer->events.end(),
                                     [](auto& e) { return e.kind == Kind::Record && e.outgoing; });
        require(records == (observer == &co ? ct.protects : st.protects),
                "record protection duplicated on partial send");
        std::uint64_t scenario_ns = 0, sum = 0, fin_batch = 0, ping_batch = 0;
        std::uint64_t previous_leaf_end = 0;
        std::map<std::uint64_t, std::uint64_t> fragment_bytes;
        for (const auto& e : observer->events) {
            if (e.kind == Kind::Assemble || e.kind == Kind::Process) {
                require(e.offset == fragment_bytes[e.message] && e.length > 0,
                        "message fragment ranges overlap or omit bytes");
                fragment_bytes[e.message] += e.length;
            }
            if (e.kind == Kind::Message)
                require(fragment_bytes[e.message] == e.plain_length,
                        "stage fragments do not cover the complete message");
            if (e.kind == Kind::Scenario)
                scenario_ns = e.end.wall - e.begin.wall;
            if (e.kind == Kind::Transition || e.kind == Kind::Assemble || e.kind == Kind::Process ||
                e.kind == Kind::Protect || e.kind == Kind::Unprotect || e.kind == Kind::Send ||
                e.kind == Kind::Receive || e.kind == Kind::Wait || e.kind == Kind::Verify) {
                require(e.begin.wall >= previous_leaf_end && e.end.wall >= e.begin.wall,
                        "leaf intervals overlap or reverse");
                previous_leaf_end = e.end.wall;
                sum += e.end.wall - e.begin.wall;
            }
            if (e.kind == Kind::Record && e.outgoing && e.type == 22)
                fin_batch = e.batch;
            if (e.kind == Kind::Record && e.outgoing && e.type == 23 && !ping_batch)
                ping_batch = e.batch;
        }
        require(sum <= scenario_ns, "leaf costs duplicated or missing parent");
        if (observer == &so && scenario == Scenario::FinishedPing)
            require(fin_batch == ping_batch, "Finished+Ping batch split");
        if (observer == &so && scenario == Scenario::ServerPing)
            require(fin_batch != ping_batch, "server-ping failed to submit Finished first");
    }
}
extern "C" void* __wrap_malloc(std::size_t);
extern "C" void* __wrap_realloc(void*, std::size_t);
extern "C" void __wrap_free(void*);
int main() {
    try {
        std::vector<std::uint8_t> abc = {'a', 'b', 'c'};
        require(turtle::sha256(abc) ==
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "SHA256 abc");
        require(turtle::sha256({}) ==
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "SHA256 empty");
        turtle::Allocations allocations(true);
        {
            turtle::AllocationScope scope(&allocations);
            auto* p = __wrap_malloc(100);
            p = __wrap_realloc(p, 173);
            __wrap_free(p);
        }
        require(allocations.value.live == 0 && allocations.value.peak == 173 &&
                    allocations.value.allocated == 273 && allocations.value.freed == 273,
                "allocation accounting");
        for (auto scenario : {turtle::Scenario::Handshake, turtle::Scenario::ServerPing,
                              turtle::Scenario::FinishedPing, turtle::Scenario::ClientRequest})
            for (bool bundle : {false, true})
                for (bool hello : {false, true})
                    exercise(scenario, bundle, hello);
        std::cout << "deterministic toy contract, SHA256 and allocator checks passed (not TLS "
                     "evidence)\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
