#include "run/runner.hpp"
#include "measure/recorder.hpp"
#include "net/transport.hpp"
#include "artifact/endpoint.hpp"
#include "artifact/json.hpp"
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>
namespace turtle::run {
namespace {
using namespace measure;
void require(bool success, const char* reason) { if (!success) throw std::runtime_error(reason); }
constexpr bool pending(std::ptrdiff_t n) { return n == TURTLE_WANT_READ || n == TURTLE_WANT_WRITE; }
bool presend(const Options& o) { return o.scenario == "S2" || o.scenario == "S4"; }
std::string command() {
    std::string s;
    require(static_cast<bool>(std::getline(std::cin, s)), "control_closed");
    return s;
}
net::Socket socket(const Options& o) {
    if (o.role == TURTLE_CLIENT) return net::connect(o.host.c_str(), o.port);
    auto listener = net::listen(o.host.c_str(), o.port);
    std::cout << "LISTEN " << net::port(listener) << std::endl;
    return net::accept(listener);
}

int preflight(const turtle_implementation& api, const Options& o) {
    bool attempted_io = false;
    turtle_transport offline{&attempted_io,
        [](void* s, void*, std::size_t) -> ptrdiff_t { *static_cast<bool*>(s) = true; return -1; },
        [](void* s, const void*, std::size_t) -> ptrdiff_t { *static_cast<bool*>(s) = true; return -1; },
        nullptr, o.auth == "mtls"};
    std::unique_ptr<void, decltype(api.release)> state(api.prepare(o.role, o.arguments.size(), o.arguments.data(), offline), api.release);
    bool prepared = state != nullptr;
    state.reset();
    const bool clock_available = measure::now().wall_available;
    bool ready = prepared && !attempted_io && clock_available && (o.role != TURTLE_SERVER || !presend(o) || api.server_first);
    PerfCounters counters(o.perf_counters);
    auto has = [&](turtle_hook h) { return (api.hooks & (1U << h)) != 0; };
    artifact::Json out{{"ready", ready}, {"implementation", api.name}, {"monotonic_clock",clock_available}, {"server_first", api.server_first != nullptr},
        {"public_io", (has(TURTLE_BIO_BEGIN) && has(TURTLE_BIO_END)) || (has(TURTLE_IO_BEGIN) && has(TURTLE_IO_END))},
        {"headers", has(TURTLE_RECORD_HEADER)}, {"perf_counters", counters.availability() == PerfAvailability::available},
        {"perf_reason", counters.reason() ? artifact::Json(counters.reason()) : artifact::Json(nullptr)}};
    if (!ready) out["reason"] = !prepared ? "prepare_failed" : attempted_io ? "unexpected_prepare_io" : !clock_available ? "monotonic_clock_unavailable" : "server_first_unsupported";
    std::cout << out.dump() << std::endl;
    return ready ? 0 : 1;
}

// Only the capability client stops. Check the complete server submission is in
// the kernel receive queue before allowing another TLS call (no stream bytes consumed).
void pause_client(net::Connection& connection, artifact::Result& result) {
    result.client_paused = true;
    std::cout << "PAUSED" << std::endl;
    const auto line = command();
    require(line.starts_with("RESUME "), "probe_resume_expected");
    auto [end, ec] = std::from_chars(line.data() + 7, line.data() + line.size(), result.server_submitted);
    require(ec == std::errc{} && end == line.data() + line.size() && result.server_submitted > 0, "probe_invalid_byte_count");
    result.queued_before_resume = connection.queued(result.server_submitted);
}

class Task {
    const turtle_implementation& api;
    void* state;
    net::Connection& connection;
    Recorder& rec;
    artifact::Result& r;
    const Options& o;
    bool started = false;
    std::vector<char> buffer;

    template<class F>
    std::ptrdiff_t invoke(Operation op, Direction dir, std::size_t requested, std::size_t pos,
                          bool first_progress, bool candidate_end, F fn, bool final_byte = false) {
        const auto id = rec.begin(Kind::call, op, dir, 0, requested);
        const bool mark_start = first_progress && !started;
        // With recording disabled only take the same minimal interval timers.
        const auto before = mark_start ? (id ? rec.event(id).begin : rec.stamp()) : Stamp{};
        const auto n = fn();
        const auto after = (id || candidate_end) ? rec.end(id, n > 0, n) : Stamp{};
        if (mark_start) { r.begin = before; r.begin_event = id; started = true; }
        if (candidate_end && n > 0 && (!final_byte || static_cast<std::size_t>(n) == requested)) {
            r.end = after; r.end_event = id;
        }
        if (id && (op == Operation::write || op == Operation::read || op == Operation::server_first)) {
            auto& event = rec.event(id);
            event.plaintext_begin = pos;
            event.plaintext_end = pos + (n > 0 ? n : 0);
        }
        return n;
    }
    void wait(std::ptrdiff_t n) { connection.wait(n == TURTLE_WANT_WRITE); }
    void handshake() {
        while (true) {
            auto n = invoke(Operation::handshake, Direction::receive, 0, 0, true, o.scenario == "S0",
                            [&] { return api.handshake(state); });
            if (n == 1) return;
            require(pending(n), "handshake_failed");
            if (o.purpose == "capability" && o.role == TURTLE_CLIENT && !r.client_paused && n == TURTLE_WANT_READ) {
                require(connection.submitted() > 0, "probe_client_hello_not_submitted");
                pause_client(connection, r);
            }
            wait(n);
        }
    }
    void send(std::string_view message, bool early, bool measure_end) {
        if (early) require(api.server_first, "server_first_unsupported");
        while (!message.empty()) {
            const auto size = o.app_chunk ? std::min(message.size(), o.app_chunk) : message.size();
            const auto n = invoke(early ? Operation::server_first : Operation::write, Direction::send,
                                  size, r.plaintext_sent, early, measure_end && size == message.size(), [&] {
                return (early ? api.server_first : api.write)(state, message.data(), size);
            }, true);
            if (pending(n)) { wait(n); continue; }
            require(n > 0 && static_cast<std::size_t>(n) <= size, "application_write_failed");
            r.plaintext_sent += n;
            message.remove_prefix(n);
        }
    }
    void receive(std::string_view expected, bool first, bool final) {
        std::size_t offset = 0;
        while (offset < expected.size()) {
            const auto remaining = expected.size() - offset;
            const auto size = o.app_chunk ? std::min(remaining, o.app_chunk) : remaining;
            const auto n = invoke(Operation::read, Direction::receive, size, r.plaintext_received, false,
                    (first && !offset), [&] {
                        return api.read(state, buffer.data() + offset, size);
                    });
            if (pending(n)) { wait(n); continue; }
            require(n > 0 && static_cast<std::size_t>(n) <= size, "application_read_failed");
            offset += n;
            r.plaintext_received += n;
        }
        const auto id = rec.begin(Kind::call, Operation::verify, Direction::receive, 0, expected.size());
        bool match = std::equal(expected.begin(), expected.end(), buffer.begin());
        if (id) {
            const auto verified = rec.end(id, match);
            if (final && match) { r.end = verified; r.end_event = id; }
            auto& e = rec.event(id);
            e.plaintext_begin = r.plaintext_received - expected.size();
            e.plaintext_end = r.plaintext_received;
        }
        if (!id && final && match) r.end = rec.stamp();
        require(match, "application_content_mismatch");
    }
public:
    Task(const turtle_implementation& a, void* s, net::Connection& c, Recorder& recorder, artifact::Result& result, const Options& opts)
        : api(a), state(s), connection(c), rec(recorder), r(result), o(opts),
          buffer(std::max({o.request.size(), o.response.size(), o.greeting.size()})) {}
    void run() {
        const bool early = presend(o), request = o.scenario == "S1" || o.scenario == "S3" || o.scenario == "S4",
                   respond = o.scenario == "S3" || o.scenario == "S4";
        if (early && o.role == TURTLE_SERVER) {
            send(o.greeting, true, o.scenario == "S2");
            if (o.purpose == "capability") {
                r.server_submitted = connection.submitted();
                require(r.server_submitted > 0, "probe_no_server_bytes");
                r.server_presend = true;
                std::cout << "PRESEND " << r.server_submitted << std::endl;
                require(command() == "CONTINUE", "probe_release_expected");
            }
        }
        handshake();
        if (o.role == TURTLE_CLIENT) {
            if (request) send(o.request, false, !respond);
            if (early) {
                receive(o.greeting, !respond, false);
                if (o.purpose == "capability") std::cout << "GREETING" << std::endl;
            }
            if (respond) receive(o.response, true, false);
        } else {
            if (request) receive(o.request, false, !respond);
            if (respond) send(o.response, false, true);
        }
        r.content_verified = true;
    }
};
}
int run(const turtle_implementation& api, const Options& o) {
    if (o.check) return preflight(api, o);
    using namespace measure;
    std::filesystem::create_directories(o.output);
    for (const auto* file : {"endpoint.json", "events.jsonl", "counters.json", "tls_send.bin", "tls_receive.bin", "wire_send.bin", "wire_receive.bin"})
        require(!std::filesystem::exists(std::filesystem::path(o.output) / file), "output_already_exists");
    artifact::Result r;
    r.role = o.role == TURTLE_CLIENT ? "client" : "server";
    r.purpose = o.purpose; r.auth = o.auth; r.scenario = o.scenario; r.measured_role = o.measured_role;
    r.recording = o.recording; r.run_id = o.run_id; r.connection_id = o.run_id;
    r.implementation = api.name; r.chunk = o.chunk;
    r.request_bytes = o.request.size(); r.response_bytes = o.response.size(); r.greeting_bytes = o.greeting.size();
    const bool measured = r.role == o.measured_role;
    r.cpu_samples = measured && o.cpu_samples;
    auto mode = !measured ? Mode::peer : o.recording == "off" ? Mode::off :
                o.recording == "basic" ? Mode::basic : Mode::detailed;
    Recorder rec(Recorder::event_capacity, measured && o.perf_counters, mode);
    try {
        net::Connection conn(socket(o), rec, o.chunk, o.timeout, o.purpose == "capability");
        auto transport = conn.transport();
        transport.mutual_auth = o.auth == "mtls";
        const auto prepare_id = rec.begin(Kind::call, Operation::prepare);
        std::unique_ptr<void, decltype(api.release)> state(api.prepare(o.role, o.arguments.size(), o.arguments.data(), transport), api.release);
        if (prepare_id) rec.end(prepare_id, state != nullptr);
        require(state != nullptr, "prepare_failed");
        Task task(api, state.get(), conn, rec, r, o); // allocate application buffers before the start barrier
        std::cout << "READY" << std::endl;
        require(command() == "START", "start_barrier_failed");
        task.run();
        turtle_handshake_info info{0, -1, nullptr, nullptr, TURTLE_PROFILE_UNSPECIFIED, -1, 0};
        require(api.query(state.get(), &info) == 1, "negotiation_query_failed");
        r.version = info.version; r.resumed = info.resumed; r.profile = info.profile; r.peer_verified = info.peer_verified; r.record_policy = info.record_policy;
        if (info.cipher) r.cipher = info.cipher;
        if (info.group) r.group = info.group;
        require(r.version == TURTLE_TLS13 && r.resumed == 0, "not_full_tls13");
        require(r.profile == (transport.mutual_auth ? TURTLE_PROFILE_MTLS_1RTT : TURTLE_PROFILE_SERVER_AUTH_1RTT),
                "authentication_policy_mismatch");
        if (o.role == TURTLE_CLIENT || transport.mutual_auth) require(r.peer_verified == 1, "peer_not_authenticated");
        else require(r.peer_verified == 0, "unexpected_client_authentication");
        r.scenario_complete = true;
        r.scenario_observations_complete = rec.complete();
        r.scenario_tls_send = r.scenario_wire_send = rec.total(Layer::wire, Direction::send);
        r.scenario_tls_receive = r.scenario_wire_receive = rec.total(Layer::wire, Direction::receive);
        r.shutdown = api.shutdown ? "failed" : "not_supported";
        if (api.shutdown) for (;;) {
            const auto id = rec.begin(Kind::call, Operation::shutdown);
            auto n = api.shutdown(state.get());
            if (id) rec.end(id, n == 1, n);
            if (!pending(n)) {
                if (n == 1) r.shutdown = "ok";
                else r.shutdown_reason = "tls_shutdown_failed";
                break;
            }
            conn.wait(n == TURTLE_WANT_WRITE);
        }
    } catch (const std::exception& error) {
        if (!r.scenario_complete) r.invalid_reason = error.what();
        else r.shutdown_reason = error.what();
    } catch (...) {
        if (!r.scenario_complete) r.invalid_reason = "implementation_exception";
        else r.shutdown_reason = "implementation_exception";
    }
    if (rec.reason()) r.observation_reason = rec.reason();
    artifact::write(o.output, rec, r);
    return r.scenario_complete ? 0 : 1;
}
}
