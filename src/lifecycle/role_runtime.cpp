#include "lifecycle/role_runtime.hpp"

#include "lifecycle/capture.hpp"
#include "lifecycle/endpoint_protocol.hpp"
#include "lifecycle/lookup_runtime.hpp"
#include "capability/capability.hpp"
#include "measure/measure.hpp"
#include "model/sample.hpp"
#include "record/record.hpp"
#include "transport/channel.hpp"
#include "transport/tcp.hpp"

#include <chrono>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <unistd.h>

namespace turtle::lifecycle::detail {
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
            throw std::runtime_error("adapter ABI v2 entry turtle_adapter_v2 is missing");
        }
        api = entry();
        if (api.version != adapter_api_version || !api.name || !api.setup || !api.declaration ||
            !api.open || !api.handshake_step || !api.peer_verification || !api.negotiated ||
            !api.app_send || !api.app_recv || !api.error || !api.close || !api.save ||
            !api.teardown) {
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
using TlsCapture = Capture<measure::Meter>;
bool keylog(void* p, const char* line, std::size_t size) noexcept {
    return static_cast<TlsCapture*>(p)->buffer.append_keylog({line, size});
}
bool plaintext(void* p, bool outgoing, unsigned type, const std::uint8_t* bytes,
               std::size_t size) noexcept {
    auto& c = *static_cast<TlsCapture*>(p);
    return c.buffer.append_plaintext(c.connection, outgoing, type, {bytes, size});
}

void configure_io_observation(model::SampleInfo& info, const model::RunConfig& config) {
    if (!config.tls.framework_io) {
        info.observation_level = "library-only";
        info.tls_stream_available = false;
        info.tls_stream_reason = "native_socket_io_not_observed";
        info.io_events_available = false;
        info.io_events_reason = "native_socket_io_not_observed";
        info.kernel_receive_events_available = false;
        info.kernel_receive_events_reason = "native_socket_io_not_observed";
        info.incomplete.push_back("native socket I/O has no framework byte or kernel capture");
    } else if (!config.channel_observer) {
        info.observation_level = "observer-disabled";
        info.tls_stream_available = false;
        info.tls_stream_reason = "channel_observer_disabled";
        info.io_events_available = false;
        info.io_events_reason = "channel_observer_disabled";
        info.kernel_receive_events_available = false;
        info.kernel_receive_events_reason = "channel_observer_disabled";
        info.incomplete.push_back("channel observer disabled; framework I/O bytes and receive events were not captured");
    }
}
} // namespace

std::vector<std::uint8_t> load_serialized_context(const model::RunConfig& config, Role role) {
    if (config.context_directory.empty())
        return {};
    std::ifstream in(std::filesystem::path(config.context_directory) /
                         (std::string(model::name(role)) + ".context.bin"),
                     std::ios::binary);
    if (!in)
        throw std::runtime_error("context input unavailable");
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

int run_tls_role(const model::RunConfig& config, Role role, std::uint64_t sample,
                 const std::string& directory, std::vector<int> sockets, int control_fd,
                 control::Deadline deadline, std::span<const std::uint8_t> saved,
                 const lookup::Snapshot* reference, const lookup::Snapshot* initial,
                 std::vector<int> lookup_sockets) {
    const std::size_t count = config.warmups + config.connections;
    record::Writer writer(directory, role, count);
    record::Buffer buffer({config.event_capacity, config.stream_capacity,
                           config.keylog_capacity, count});
    model::SampleInfo info;
    info.sample = sample;
    info.batch = config.batch;
    info.role = role;
    info.pid = ::getpid();
    info.config = config;
    configure_io_observation(info, config);
    measure::Meter meter(config.mode, config.perf, config.perf_scope);
    TlsCapture capture{meter, buffer};
    control::Waiter parent(control_fd);
    ChildProtocol protocol(parent);
    std::vector<std::unique_ptr<control::WaitSet>> wait_sets;
    std::vector<model::SocketSettings> settings;
    wait_sets.reserve(count);
    settings.reserve(count);
    detail::ClientLookupRuntime client_lookup(config, meter, sample, directory, control_fd,
                                              reference, initial, std::move(lookup_sockets));
    bool valid = true;
    std::string failure;
    std::optional<model::ConnectionInfo> active_connection;
    try {
        info.environment = capability::inspect_environment();
        const auto placement_warnings =
            capability::cpu_selection_warnings(config, info.environment);
        info.environment.warnings.insert(info.environment.warnings.end(),
                                         placement_warnings.begin(),
                                         placement_warnings.end());
        info.capabilities = meter.capabilities();
        meter.require_requested_scope();
        if (config.pin_cores) {
            const int cpu = role == Role::Client ? config.client_cpu : config.server_cpu;
            std::string reason;
            if (!capability::pin_to_cpu(cpu, reason))
                throw std::runtime_error("endpoint CPU affinity failed: " + reason);
            info.capabilities.affinity = true; info.pinned_cpu = cpu;
        }
        info.calibration = meter.calibrate(config.calibration_samples);
        for (int fd : sockets) {
            settings.push_back(transport::configure(fd, config.tcp_nodelay,
                config.socket_send_buffer, config.socket_receive_buffer,
                config.kernel_timestamps));
            info.capabilities.kernel_timestamp_configured =
                settings.back().kernel_timestamps &&
                (settings.size() == 1 || info.capabilities.kernel_timestamp_configured);
            wait_sets.push_back(std::make_unique<control::WaitSet>(fd, control_fd));
            if (auto reason = tcp::check_ready(fd); !reason.empty())
                throw std::runtime_error(reason);
        }
        client_lookup.prepare(info);
        Module module((std::filesystem::path(config.adapter_directory) /
            ((role == Role::Client ? config.client_adapter : config.server_adapter) + ".so")).string());
        auto& api = module.api;
        HostServices host{meter.allocator(), {&capture, keylog}, {&capture, plaintext},
                          config.mode == model::Mode::Memory, config.mode == model::Mode::Trace};
        info.loaded_context_size = saved.size();
        if (!saved.empty()) info.loaded_context_hash = model::fingerprint(saved);
        const auto setup_begin = meter.read();
        std::unique_ptr<Context, decltype(api.teardown)> context(
            api.setup(role, config.tls, host, saved), api.teardown);
        const auto setup_end = meter.read();
        if (!context) throw std::runtime_error("adapter setup failed");
        std::vector<std::uint8_t> outgoing(config.tls.application_bytes), incoming(outgoing.size());
        for (std::size_t i = 0; i < outgoing.size(); ++i)
            outgoing[i] = static_cast<std::uint8_t>((i + config.seed) % 251);
        info.connections.reserve(count);
        if (config.isolate) control::isolate();
        send(parent, control::MessageKind::TcpReady, deadline, sample);
        auto start = protocol.receive(deadline);
        if (start.kind != control::MessageKind::Start)
            throw std::runtime_error("endpoint expected START");
        info.declaration = api.declaration(context.get());
        if (!saved.empty() && !info.declaration.context_serialization)
            throw std::runtime_error("adapter cannot restore context");
        info.capabilities.heap_tracking &= info.declaration.allocator_hooks;
        capture.heap_supported = info.capabilities.heap_tracking;
        auto setup_event = [&](model::EventKind kind, model::Snapshot value) {
            if (!capture.heap_supported) value.heap.reset();
            model::Event event; event.kind = kind; event.call = model::Call::Setup;
            event.sequence = ++capture.sequence; event.snapshot = value; buffer.append(event);
        };
        setup_event(model::EventKind::SetupBegin, setup_begin);
        setup_event(model::EventKind::SetupEnd, setup_end);
        if (config.tls.framework_io && config.channel_observer &&
            info.capabilities.kernel_timestamp_configured) {
            info.kernel_receive_events_available = true;
            info.kernel_receive_events_reason.clear();
        }
        if (info.declaration.is_mock)
            info.incomplete.push_back("mock: no TLS encryption or certificate verification");
        info.clock_start = measure::clock_pair();
        capture.event(model::EventKind::TcpReady);

        for (std::size_t i = 0; i < count; ++i) {
            active_connection.emplace();
            auto& connection = *active_connection;
            connection.index = i;
            connection.warmup = i < config.warmups;
            connection.socket = settings[i];
            connection.tcp_start = tcp::read_tcp_info(sockets[i]);
            client_lookup.run_connection(i, protocol, parent, deadline);
            capture.connection = i; capture.sent = capture.received = capture.first_receive = 0;
            transport::Channel channel{sockets[i], &capture,
                                       config.channel_observer ? TlsCapture::observe : nullptr};
            auto io = channel.io(); capture.call = model::Call::Open;
            capture.event(model::EventKind::OpenBegin);
            std::unique_ptr<Connection, decltype(api.close)> tls(api.open(context.get(), io), api.close);
            capture.event(model::EventKind::OpenEnd);
            if (!tls) throw std::runtime_error("adapter open failed");
            send(parent, control::MessageKind::TcpReady, deadline, sample, i);
            auto open_release = protocol.receive(deadline);
            if (open_release.kind != control::MessageKind::Start || open_release.connection != i)
                throw std::runtime_error("endpoint open release missing");
            auto adapter_failure = [&](const char* operation) {
                const char* detail = api.error ? api.error(tls.get()) : nullptr;
                throw std::runtime_error(std::string(operation) + ": " +
                    (detail && *detail ? detail : "adapter did not provide a diagnostic"));
            };
            if (role == Role::Client)
                connection.start_sequence = capture.sequence + 1;
            else if (!config.tls.framework_io || !config.channel_observer) {
                connection.primary_window_available = false;
                connection.primary_window_reason = "server_first_receive_not_observed";
            }
            for (;;) {
                auto step = capture.invoke(model::Call::Handshake,
                    [&] { return api.handshake_step(tls.get()); });
                if (step == Step::Done) break;
                if (step == Step::Failed) adapter_failure("handshake failed");
                capture.event(model::EventKind::WaitBegin);
                protocol.wait(*wait_sets[i], step == Step::WantWrite, deadline);
                capture.event(model::EventKind::WaitEnd);
            }
            connection.verification = capture.invoke(model::Call::Verification,
                [&] { return api.peer_verification(tls.get()); });
            if (connection.verification == Verification::Failed ||
                ((role == Role::Client || config.tls.mutual_auth) &&
                 connection.verification != Verification::Passed))
                throw std::runtime_error("peer verification did not pass");
            auto application = [&](bool sending) {
                std::size_t offset = 0;
                while (offset < outgoing.size()) {
                    const auto remaining = outgoing.size() - offset;
                    auto result = capture.invoke(sending ? model::Call::AppSend : model::Call::AppRecv,
                        [&] { return sending
                            ? api.app_send(tls.get(), outgoing.data() + offset, remaining)
                            : api.app_recv(tls.get(), incoming.data() + offset, remaining); }, remaining);
                    if (result.step == Step::Failed) adapter_failure(sending ? "application send failed" : "application receive failed");
                    if (result.bytes > remaining) throw std::runtime_error("application returned too many bytes");
                    if (result.step == Step::WantRead || result.step == Step::WantWrite) {
                        if (result.bytes) throw std::runtime_error("retry returned bytes");
                        capture.event(model::EventKind::WaitBegin);
                        protocol.wait(*wait_sets[i], result.step == Step::WantWrite, deadline);
                        capture.event(model::EventKind::WaitEnd);
                        continue;
                    }
                    if (!result.bytes) throw std::runtime_error("application made no progress");
                    offset += result.bytes;
                }
            };
            if (role == Role::Client) { application(true); application(false); }
            else { application(false); if (incoming != outgoing) throw std::runtime_error("ping mismatch"); application(true); }
            if (incoming != outgoing) throw std::runtime_error("pong mismatch");
            connection.application_verified = true;
            client_lookup.scenario_end();
            connection.end_sequence = capture.sequence;
            if (role == Role::Server && capture.first_receive)
                connection.start_sequence = capture.first_receive;
            if (connection.start_sequence) {
                connection.primary_window_available = true;
                connection.primary_window_reason.clear();
            }
            connection.negotiated = capture.invoke(model::Call::Negotiated,
                [&] { return api.negotiated(tls.get()); });
            if (!info.declaration.is_mock) {
                const auto& n = connection.negotiated;
                if (n.version != "TLS1.3" || n.resumed || n.hello_retry_request)
                    throw std::runtime_error("not a normal full TLS 1.3 handshake");
                auto check = [&](const std::string& actual, const std::string& wanted, const char* field) {
                    if (actual.empty()) info.incomplete.push_back(std::string("negotiated ") + field + " is unobserved; requested value is not a measurement");
                    else if (actual != wanted) throw std::runtime_error(std::string("negotiated ") + field + " differs from requested profile");
                };
                check(n.cipher, config.tls.cipher, "cipher"); check(n.group, config.tls.group, "group");
                check(n.signature, config.tls.signature, "signature");
                if ((role == Role::Client || config.tls.mutual_auth) && !n.peer_certificate_present)
                    throw std::runtime_error("required peer certificate was not observed");
            }
            connection.tcp_end = tcp::read_tcp_info(sockets[i]);
            info.connections.push_back(std::move(connection));
            active_connection.reset();
            send(parent, control::MessageKind::ConnectionComplete, deadline, sample, i);
            auto continue_message = protocol.receive(deadline);
            if (continue_message.kind != control::MessageKind::Start || continue_message.connection != i)
                throw std::runtime_error("endpoint connection release missing");
            capture.call = model::Call::Close; capture.event(model::EventKind::CloseBegin);
            tls.reset(); capture.event(model::EventKind::CloseEnd);
            ::close(sockets[i]); sockets[i] = -1;
            client_lookup.close_connection(i);
        }
        auto output = api.save(context.get()); info.saved_context_size = output.size();
        capture.call = model::Call::Save; capture.event(model::EventKind::Save);
        writer.write_context(output); context.reset(); info.clock_end = measure::clock_pair();
        info.perf_complete = info.capabilities.perf;
        for (const auto& event : buffer.events())
            if (!event.snapshot.cycles || !event.snapshot.instructions ||
                !event.snapshot.perf_enabled || !event.snapshot.perf_running ||
                *event.snapshot.perf_running == 0 ||
                *event.snapshot.perf_running < *event.snapshot.perf_enabled)
                info.perf_complete = false;
        if (buffer.overflowed() || client_lookup.overflowed())
            throw std::runtime_error("capture buffer overflow");
    } catch (const AbortRequested&) {
        if (active_connection) {
            const auto active_index = active_connection->index;
            active_connection->tcp_end = tcp::read_tcp_info(sockets[active_index]);
            info.connections.push_back(std::move(*active_connection));
            client_lookup.mark_partial(active_index, "parent requested abort");
            active_connection.reset();
        }
        valid = false;
        failure = "parent requested abort";
        info.valid = false;
        info.invalid_reason = failure;
        info.clock_end = measure::clock_pair();
    } catch (const std::exception& error) {
        if (active_connection) {
            const auto active_index = active_connection->index;
            active_connection->tcp_end = tcp::read_tcp_info(sockets[active_index]);
            info.connections.push_back(std::move(*active_connection));
            client_lookup.mark_partial(active_index, error.what());
            active_connection.reset();
        }
        valid = false; failure = error.what(); info.valid = false; info.invalid_reason = failure;
        info.clock_end = measure::clock_pair();
        try { send(parent, control::MessageKind::Failed, deadline, sample, 0, false, {}, 0, 0,
                   failure); } catch (...) {}
    }
    close_all(sockets); client_lookup.close_sockets();
    auto flush_deadline = deadline + std::chrono::milliseconds(config.flush_grace_ms);
    try {
        const auto command = protocol.flush(flush_deadline);
        flush_deadline = protocol.cleanup_deadline();
        if (command.kind == control::MessageKind::AbortFlush && valid) {
            valid = false;
            failure = "parent aborted after participant completion";
            info.valid = false;
            info.invalid_reason = failure;
        } else if (command.kind == control::MessageKind::Flush && !valid) {
            throw std::runtime_error("invalid endpoint received normal FLUSH");
        }
    } catch (const std::exception& error) {
        valid = false; if (failure.empty()) failure = error.what();
        info.valid = false; info.invalid_reason = failure;
    }
    try {
        writer.write(info, buffer);
        client_lookup.write(valid, failure);
        send(parent, control::MessageKind::Flushed, flush_deadline, sample);
    } catch (const std::exception& error) {
        valid = false;
        const std::string flush_failure = error.what();
        if (failure.empty()) failure = flush_failure;
        try {
            send(parent, control::MessageKind::Failed, flush_deadline, sample, 0, false, {}, 0,
                 0, flush_failure);
        } catch (const std::exception& notify_error) {
            std::cerr << model::name(role) << " flush failure: " << flush_failure
                      << "; failure notification: " << notify_error.what() << '\n';
        }
    }
    return valid ? 0 : 1;
}

} // namespace turtle::lifecycle::detail
