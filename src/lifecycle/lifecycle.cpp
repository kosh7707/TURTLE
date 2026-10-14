#include "lifecycle/lifecycle.hpp"
#include "capability/capability.hpp"
#include "control/control.hpp"
#include "measure/measure.hpp"
#include "record/record.hpp"
#include "transport/channel.hpp"
#include "transport/tcp.hpp"
#include <algorithm>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sched.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <type_traits>
#include <unistd.h>
namespace turtle::lifecycle {
namespace {
struct Module {
    void* handle = nullptr;
    ImplementationApi api;
    explicit Module(const std::string& path) {
        handle = ::dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!handle)
            throw std::runtime_error(::dlerror());
        auto entry = reinterpret_cast<AdapterEntry>(::dlsym(handle, adapter_entry_name));
        if (!entry) {
            ::dlclose(handle);
            handle = nullptr;
            throw std::runtime_error("adapter entry missing");
        }
        api = entry();
        if (api.version != adapter_api_version || !api.name || !api.setup || !api.declaration ||
            !api.open || !api.handshake_step || !api.peer_verification || !api.negotiated ||
            !api.app_send || !api.app_recv || !api.close || !api.save || !api.teardown) {
            ::dlclose(handle);
            handle = nullptr;
            throw std::runtime_error("incomplete adapter API");
        }
    }
    ~Module() {
        if (handle)
            ::dlclose(handle);
    }
};
struct Capture {
    measure::Meter& meter;
    record::Buffer& buffer;
    std::size_t connection = 0;
    std::uint64_t sequence = 0, call_id = 0, sent = 0, received = 0;
    model::Call call = model::Call::None;
    std::uint64_t first_receive = 0;
    bool heap_supported = false;
    model::Snapshot snapshot() noexcept {
        auto value = meter.read();
        if (!heap_supported)
            value.heap.reset();
        return value;
    }
    void event(model::EventKind kind, model::Location location = model::Location::Boundary,
               std::int64_t result = 0, std::size_t requested = 0,
               std::size_t transferred = 0) noexcept {
        model::Event e;
        e.kind = kind;
        e.location = location;
        e.result = result;
        e.requested = requested;
        e.transferred = transferred;
        e.connection = connection;
        e.sequence = ++sequence;
        e.call = call;
        e.call_id = call_id;
        e.snapshot = snapshot();
        buffer.append(e);
    }
    static void observe(void* p, const transport::Observation& o) noexcept {
        auto& c = *static_cast<Capture*>(p);
        model::Event e;
        e.connection = c.connection;
        e.sequence = ++c.sequence;
        e.call = c.call;
        e.call_id = c.call_id;
        e.snapshot = c.snapshot();
        e.kind =
            o.sending
                ? (o.entering ? model::EventKind::IoSendEnter : model::EventKind::IoSendReturn)
                : (o.entering ? model::EventKind::IoRecvEnter : model::EventKind::IoRecvReturn);
        auto& offset = o.sending ? c.sent : c.received;
        e.stream_begin = offset;
        e.requested = o.requested;
        if (!o.entering) {
            e.transferred = o.result.bytes;
            e.result = static_cast<int>(o.result.status);
            e.system_error = o.result.system_error;
            offset += o.result.bytes;
        }
        e.stream_end = offset;
        c.buffer.append(e);
        if (!o.entering && o.result.bytes) {
            c.buffer.append_bytes(c.connection,
                                  o.sending ? model::Direction::Sent : model::Direction::Received,
                                  {o.data, o.result.bytes});
            if (!o.sending && !c.first_receive)
                c.first_receive = e.sequence;
            if (o.kernel_realtime_ns) {
                e.kind = model::EventKind::KernelRx;
                e.location = model::Location::Kernel;
                e.sequence = ++c.sequence;
                e.raw_timestamp_ns = o.kernel_realtime_ns;
                c.buffer.append(e);
            }
        }
    }
    template <class F> auto invoke(model::Call operation, F&& f, std::size_t requested = 0) {
        call = operation;
        ++call_id;
        event(model::EventKind::CallBegin, model::Location::Boundary, 0, requested);
        auto result = f();
        std::int64_t code = 0;
        std::size_t transferred = 0;
        if constexpr (std::is_same_v<decltype(result), AppResult>) {
            code = static_cast<int>(result.step);
            transferred = result.bytes;
        } else if constexpr (std::is_enum_v<decltype(result)>)
            code = static_cast<int>(result);
        event(model::EventKind::CallEnd, model::Location::Boundary, code, requested, transferred);
        return result;
    }
    void wait(Step step, control::Waiter& waiter, control::Deadline deadline) {
        if (step != Step::WantRead && step != Step::WantWrite)
            throw std::runtime_error("adapter operation failed");
        event(model::EventKind::WaitBegin);
        waiter.wait(step == Step::WantWrite, deadline);
        event(model::EventKind::WaitEnd);
    }
};
bool keylog(void* p, const char* line, std::size_t size) noexcept {
    return static_cast<Capture*>(p)->buffer.append_keylog({line, size});
}
bool plaintext(void* p, bool outgoing, unsigned type, const std::uint8_t* bytes,
               std::size_t size) noexcept {
    auto& c = *static_cast<Capture*>(p);
    return c.buffer.append_plaintext(c.connection, outgoing, type, {bytes, size});
}
std::vector<std::uint8_t> load_context(const model::RunConfig& config, Role role) {
    if (config.context_directory.empty())
        return {};
    std::ifstream in(std::filesystem::path(config.context_directory) /
                         (std::string(model::name(role)) + ".context.bin"),
                     std::ios::binary);
    if (!in)
        throw std::runtime_error("context input unavailable");
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
int endpoint(const model::RunConfig& config, Role role, std::uint64_t sample,
             const std::string& directory, int listener, std::uint16_t port, int control_fd,
             control::Deadline deadline) {
    const std::size_t count = config.warmups + 1;
    record::Writer writer(directory, role, count);
    record::Buffer buffer(
        {config.event_capacity, config.stream_capacity, config.keylog_capacity, count});
    model::SampleInfo info;
    info.sample = sample;
    info.batch = config.batch;
    info.role = role;
    info.pid = ::getpid();
    info.config = config;
    measure::Meter meter(config.mode, config.perf);
    Capture capture{meter, buffer};
    std::vector<int> sockets;
    sockets.reserve(count);
    std::vector<std::unique_ptr<control::Waiter>> waiters;
    waiters.reserve(count);
    control::Waiter control_waiter(control_fd);
    try {
        info.environment = capability::inspect_environment();
        info.capabilities = meter.capabilities();
        if (config.pin_cores) {
            const int requested_cpu = role == Role::Client ? config.client_cpu : config.server_cpu;
            std::string reason;
            if (!capability::pin_to_cpu(requested_cpu, reason))
                throw std::runtime_error("endpoint CPU affinity failed: " + reason);
            info.capabilities.affinity = true;
            info.pinned_cpu = requested_cpu;
        }
        info.calibration = meter.calibrate(config.calibration_samples);
        Module module(
            (std::filesystem::path(config.adapter_directory) /
             ((role == Role::Client ? config.client_adapter : config.server_adapter) + ".so"))
                .string());
        auto& api = module.api;
        HostServices host{meter.allocator(),
                          {&capture, keylog},
                          {&capture, plaintext},
                          config.mode == model::Mode::Memory,
                          config.mode == model::Mode::Trace};
        auto saved = load_context(config, role);
        info.loaded_context_size = saved.size();
        const auto setup_begin = meter.read();
        std::unique_ptr<Context, decltype(api.teardown)> context(
            api.setup(role, config.tls, host, saved), api.teardown);
        const auto setup_end = meter.read();
        if (!context)
            throw std::runtime_error("adapter setup failed");
        info.declaration = api.declaration(context.get());
        if (!saved.empty() && !info.declaration.context_serialization)
            throw std::runtime_error("adapter cannot restore context");
        info.capabilities.heap_tracking =
            info.capabilities.heap_tracking && info.declaration.allocator_hooks;
        capture.heap_supported = info.capabilities.heap_tracking;
        auto setup_event = [&](model::EventKind kind, model::Snapshot snapshot) {
            if (!capture.heap_supported)
                snapshot.heap.reset();
            model::Event event;
            event.kind = kind;
            event.call = model::Call::Setup;
            event.sequence = ++capture.sequence;
            event.snapshot = snapshot;
            buffer.append(event);
        };
        setup_event(model::EventKind::SetupBegin, setup_begin);
        setup_event(model::EventKind::SetupEnd, setup_end);
        if (!config.tls.framework_io) {
            info.observation_level = "library-only";
            info.incomplete.push_back("native socket I/O has no framework byte or kernel capture");
        }
        if (info.declaration.is_mock)
            info.incomplete.push_back("mock: no TLS encryption or certificate verification");
        for (std::size_t i = 0; i < count; ++i) {
            int fd = role == Role::Server ? tcp::accept_one(listener) : tcp::connect_loopback(port);
            sockets.push_back(fd);
            waiters.push_back(std::make_unique<control::Waiter>(fd));
            bool stamps =
                transport::configure(fd, config.tcp_nodelay, config.socket_send_buffer,
                                     config.socket_receive_buffer, config.kernel_timestamps);
            info.capabilities.kernel_timestamp_configured = stamps;
            if (auto reason = tcp::check_ready(fd); !reason.empty())
                throw std::runtime_error(reason);
        }
        if (listener >= 0) {
            ::close(listener);
            listener = -1;
        }
        std::vector<std::uint8_t> outgoing(config.tls.application_bytes),
            incoming(config.tls.application_bytes);
        for (std::size_t i = 0; i < outgoing.size(); ++i)
            outgoing[i] = static_cast<std::uint8_t>((i + config.seed) % 251);
        info.connections.reserve(count);
        control::barrier(control_waiter, deadline);
        if (config.isolate)
            control::isolate();
        info.clock_start = measure::clock_pair();
        capture.event(model::EventKind::TcpReady);
        for (std::size_t i = 0; i < count; ++i) {
            capture.connection = i;
            capture.sent = capture.received = capture.first_receive = 0;
            model::ConnectionInfo connection;
            connection.index = i;
            connection.warmup = i < config.warmups;
            transport::Channel channel{sockets[i], &capture, Capture::observe};
            auto io = channel.io();
            capture.call = model::Call::Open;
            capture.event(model::EventKind::OpenBegin);
            std::unique_ptr<Connection, decltype(api.close)> tls(api.open(context.get(), io),
                                                                 api.close);
            capture.event(model::EventKind::OpenEnd);
            if (!tls)
                throw std::runtime_error("adapter open failed");
            control::barrier(control_waiter, deadline);
            auto adapter_failure = [&](const char* operation) {
                const char* detail = api.error ? api.error(tls.get()) : nullptr;
                throw std::runtime_error(
                    std::string(operation) + ": " +
                    (detail && *detail ? detail : "adapter did not provide a diagnostic"));
            };
            connection.start_sequence = capture.sequence + 1;
            for (;;) {
                if (std::chrono::steady_clock::now() >= deadline)
                    throw std::runtime_error("handshake deadline exceeded");
                auto step = capture.invoke(model::Call::Handshake,
                                           [&] { return api.handshake_step(tls.get()); });
                if (step == Step::Done)
                    break;
                if (step == Step::Failed)
                    adapter_failure("handshake failed");
                capture.wait(step, *waiters[i], deadline);
            }
            connection.verification = capture.invoke(
                model::Call::Verification, [&] { return api.peer_verification(tls.get()); });
            if (connection.verification == Verification::Failed ||
                ((role == Role::Client || config.tls.mutual_auth) &&
                 connection.verification != Verification::Passed))
                throw std::runtime_error("peer verification did not pass");
            auto application = [&](bool sending) {
                std::size_t offset = 0;
                while (offset < outgoing.size()) {
                    if (std::chrono::steady_clock::now() >= deadline)
                        throw std::runtime_error("application deadline exceeded");
                    const auto remaining = outgoing.size() - offset;
                    auto r = capture.invoke(
                        sending ? model::Call::AppSend : model::Call::AppRecv,
                        [&] {
                            return sending ? api.app_send(tls.get(), outgoing.data() + offset,
                                                          remaining)
                                           : api.app_recv(tls.get(), incoming.data() + offset,
                                                          remaining);
                        },
                        remaining);
                    if (r.step == Step::Failed)
                        adapter_failure(sending ? "application send failed"
                                                : "application receive failed");
                    if (r.bytes > remaining)
                        throw std::runtime_error("application returned too many bytes");
                    if (r.step == Step::WantRead || r.step == Step::WantWrite) {
                        if (r.bytes)
                            throw std::runtime_error("retry returned bytes");
                        capture.wait(r.step, *waiters[i], deadline);
                        continue;
                    }
                    if (!r.bytes)
                        throw std::runtime_error("application made no progress");
                    offset += r.bytes;
                }
            };
            if (role == Role::Client) {
                application(true);
                application(false);
            } else {
                application(false);
                if (incoming != outgoing)
                    throw std::runtime_error("ping mismatch");
                application(true);
            }
            if (incoming != outgoing)
                throw std::runtime_error("pong mismatch");
            connection.application_verified = true;
            connection.end_sequence = capture.sequence;
            if (role == Role::Server && capture.first_receive)
                connection.start_sequence = capture.first_receive;
            // String-valued metadata and validation belong after the measured endpoint boundary.
            connection.negotiated =
                capture.invoke(model::Call::Negotiated, [&] { return api.negotiated(tls.get()); });
            if (!info.declaration.is_mock) {
                const auto& negotiated = connection.negotiated;
                if (negotiated.version != "TLS1.3" || negotiated.resumed ||
                    negotiated.hello_retry_request)
                    throw std::runtime_error("not a normal full TLS 1.3 handshake");
                auto check_field = [&](const std::string& actual, const std::string& requested,
                                       const char* field) {
                    if (actual.empty())
                        info.incomplete.push_back(
                            std::string("negotiated ") + field +
                            " is unobserved; requested value is not a measurement");
                    else if (actual != requested)
                        throw std::runtime_error(std::string("negotiated ") + field +
                                                 " differs from requested profile");
                };
                check_field(negotiated.cipher, config.tls.cipher, "cipher");
                check_field(negotiated.group, config.tls.group, "group");
                check_field(negotiated.signature, config.tls.signature, "signature");
                if ((role == Role::Client || config.tls.mutual_auth) &&
                    !negotiated.peer_certificate_present)
                    throw std::runtime_error("required peer certificate was not observed");
            }
            info.connections.push_back(std::move(connection));
            control::barrier(control_waiter, deadline);
            capture.call = model::Call::Close;
            capture.event(model::EventKind::CloseBegin);
            tls.reset();
            capture.event(model::EventKind::CloseEnd);
            ::close(sockets[i]);
            sockets[i] = -1;
        }
        auto output = api.save(context.get());
        info.saved_context_size = output.size();
        capture.call = model::Call::Save;
        capture.event(model::EventKind::Save);
        writer.write_context(output);
        context.reset();
        info.clock_end = measure::clock_pair();
        info.perf_complete = info.capabilities.perf;
        for (const auto& e : buffer.events())
            if (!e.snapshot.cycles || !e.snapshot.instructions || !e.snapshot.perf_enabled ||
                !e.snapshot.perf_running || *e.snapshot.perf_running < *e.snapshot.perf_enabled)
                info.perf_complete = false;
        if (buffer.overflowed())
            throw std::runtime_error("capture buffer overflow");
    } catch (const std::exception& error) {
        info.valid = false;
        info.invalid_reason = error.what();
        info.clock_end = measure::clock_pair();
    }
    for (int fd : sockets)
        if (fd >= 0)
            ::close(fd);
    if (listener >= 0)
        ::close(listener);
    writer.write(info, buffer);
    return info.valid ? 0 : 1;
}
} // namespace
int run(const model::RunConfig& input) {
    auto config = input;
    auto environment = capability::inspect_environment();
    capability::choose_cpus(config, environment);
    cpu_set_t original_affinity;
    const bool have_affinity =
        ::sched_getaffinity(0, sizeof original_affinity, &original_affinity) == 0;
    std::filesystem::create_directories(config.output_directory);
    for (std::uint64_t sample = 1; sample <= config.samples; ++sample) {
        std::ostringstream name;
        name << "sample-" << std::setw(6) << std::setfill('0') << sample;
        auto directory = (std::filesystem::path(config.output_directory) / name.str()).string();
        if (!std::filesystem::create_directory(directory))
            throw std::runtime_error("sample directory already exists");
        auto listener = tcp::listen_loopback();
        int pair[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) {
            ::close(listener.fd);
            throw std::runtime_error("control socketpair failed");
        }
        auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(config.timeout_ms);
        auto spawn = [&](Role role) {
            auto pid = ::fork();
            if (pid != 0)
                return pid;
            int index = role == Role::Server ? 0 : 1;
            ::close(pair[1 - index]);
            if (role == Role::Client)
                ::close(listener.fd);
            int result = 1;
            try {
                result = endpoint(config, role, sample, directory,
                                  role == Role::Server ? listener.fd : -1, listener.port,
                                  pair[index], deadline);
            } catch (const std::exception& e) {
                std::cerr << model::name(role) << ": " << e.what() << '\n';
            }
            ::close(pair[index]);
            ::_exit(result);
        };
        if (config.pin_cores && have_affinity &&
            ::sched_setaffinity(0, sizeof original_affinity, &original_affinity))
            throw std::runtime_error("cannot restore director affinity before fork");
        auto server = spawn(Role::Server);
        auto client = server < 0 ? -1 : spawn(Role::Client);
        ::close(listener.fd);
        ::close(pair[0]);
        ::close(pair[1]);
        bool ok = server > 0 && client > 0;
        std::string invalid_reason =
            "endpoint failed or sample deadline exceeded; inspect role records";
        if (config.pin_cores) {
            std::string reason;
            if (!capability::pin_to_cpu(config.director_cpu, reason)) {
                ok = false;
                invalid_reason = "director CPU affinity failed: " + reason;
            }
        }
        if (!control::reap(server, client, ok ? deadline : std::chrono::steady_clock::now()))
            ok = false;
        std::ofstream status(std::filesystem::path(directory) / "director.txt");
        status << (ok ? "valid\n" : "invalid: " + invalid_reason + "\n");
        if (config.pin_cores && have_affinity)
            ::sched_setaffinity(0, sizeof original_affinity, &original_affinity);
        if (!ok)
            return 1;
    }
    return 0;
}
} // namespace turtle::lifecycle
