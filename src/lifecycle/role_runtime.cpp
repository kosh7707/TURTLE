#include "lifecycle/role_runtime.hpp"

#include "capability/capability.hpp"
#include "lifecycle/capture.hpp"
#include "lifecycle/endpoint_protocol.hpp"
#include "lifecycle/lookup_runtime.hpp"
#include "lifecycle/peer_session.hpp"
#include "measure/measure.hpp"
#include "model/sample.hpp"
#include "record/record.hpp"
#include "transport/channel.hpp"
#include "transport/tcp.hpp"
#include <nlohmann/json.hpp>
#include <poll.h>

#include <algorithm>
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
    struct Unload {
        void operator()(void* handle) const noexcept {
            ::dlclose(handle);
        }
    };
    std::unique_ptr<void, Unload> handle;
    ImplementationApi api;
    Module(const std::string& path, AdapterEntry builtin) {
        if (builtin) {
            api = builtin();
        } else {
            handle.reset(::dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL));
            if (!handle)
                throw std::runtime_error(::dlerror());
            auto entry = reinterpret_cast<AdapterEntry>(::dlsym(handle.get(), adapter_entry_name));
            if (!entry) {
                throw std::runtime_error("adapter ABI v3 entry turtle_adapter_v3 is missing");
            }
            api = entry();
        }
        if (api.version != adapter_api_version || !api.name || !api.setup || !api.declaration ||
            !api.open || !api.handshake_step || !api.peer_verification || !api.negotiated ||
            !api.app_send || !api.app_recv || !api.error || !api.close || !api.save ||
            !api.teardown) {
            throw std::runtime_error("incomplete adapter API");
        }
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
                 const std::string& directory, PeerSession& session,
                 const tcp::DialAddress& address, control::Deadline deadline, AdapterEntry builtin,
                 std::span<const std::uint8_t> saved, const lookup::Snapshot* reference,
                 const lookup::Snapshot* initial) {
    const std::size_t count = config.warmups + config.connections;
    record::Writer writer(directory, role, count);
    record::Buffer buffer(
        {config.event_capacity, config.stream_capacity, config.keylog_capacity, count});
    model::SampleInfo info;
    info.sample = sample;
    info.batch = config.batch;
    info.role = role;
    info.pid = ::getpid();
    info.config = config;
    info.preparation = session.status();
    info.failure_phase = "setup";
    if (!config.tls.framework_io || !config.channel_observer) {
        const bool native_io = !config.tls.framework_io;
        const char* reason =
            native_io ? "native_socket_io_not_observed" : "channel_observer_disabled";
        info.observation_level = native_io ? "library-only" : "observer-disabled";
        info.tls_stream_available = false;
        info.io_events_available = false;
        info.kernel_receive_events_available = false;
        info.tls_stream_reason = reason;
        info.io_events_reason = reason;
        info.kernel_receive_events_reason = reason;
        info.incomplete.push_back(native_io
                                      ? "native socket I/O has no framework byte or kernel capture"
                                      : "channel observer disabled; framework I/O bytes and "
                                        "receive events were not captured");
    }
    measure::Meter meter(config.mode, config.perf, config.perf_scope);
    TlsCapture capture{meter, buffer};
    const int control_fd = session.peer();
    const int listener = session.listener();
    control::Waiter peer(control_fd);
    PeerProtocol protocol(peer, sample);
    std::vector<int> sockets(count, -1);
    std::unique_ptr<control::WaitSet> accept_wait;
    detail::ClientLookupRuntime client_lookup(config, meter, sample, directory, reference, initial);
    std::optional<model::ConnectionInfo> active_connection;
    std::optional<control::Deadline> cleanup_deadline;
    auto record_failure = [&](const char* reason) {
        info.preparation = session.status();
        if (active_connection) {
            const auto index = active_connection->index;
            active_connection->tcp_end = tcp::read_tcp_info(sockets[index]);
            info.connections.push_back(std::move(*active_connection));
            client_lookup.mark_partial(index, reason);
            active_connection.reset();
        }
        info.valid = false;
        info.invalid_reason = reason;
        info.clock_end = measure::clock_pair();
    };
    try {
        info.environment = capability::inspect_environment();
        const auto placement_warnings =
            capability::cpu_selection_warnings(config, info.environment);
        info.environment.warnings.insert(info.environment.warnings.end(),
                                         placement_warnings.begin(), placement_warnings.end());
        info.capabilities = meter.capabilities();
        meter.require_requested_scope();
        if (config.pin_cores) {
            const int cpu = config.cpu;
            std::string reason;
            if (!capability::pin_to_cpu(cpu, reason))
                throw std::runtime_error("endpoint CPU affinity failed: " + reason);
            info.capabilities.affinity = true;
            info.pinned_cpu = cpu;
        }
        info.calibration = meter.calibrate(config.calibration_samples);
        if (listener >= 0) {
            tcp::nonblocking_listener(listener);
            accept_wait = std::make_unique<control::WaitSet>(listener, control_fd, false);
        }
        client_lookup.prepare(info, deadline);
        const auto module_begin = meter.read();
        Module module(config.adapter_path, builtin);
        const auto module_end = meter.read();
        auto& api = module.api;
        info.config.implementation = api.name();
        HostServices host{meter.allocator(),
                          {&capture, keylog},
                          {&capture, plaintext},
                          config.mode == model::Mode::Memory,
                          config.mode == model::Mode::Trace,
                          {&capture, TlsCapture::trace}};
        info.loaded_context_size = saved.size();
        if (!saved.empty())
            info.loaded_context_hash = model::fingerprint(saved);
        const auto setup_begin = meter.read();
        std::unique_ptr<Context, decltype(api.teardown)> context(
            api.setup(role, config.tls, host, saved), api.teardown);
        const auto setup_end = meter.read();
        if (!context)
            throw std::runtime_error("adapter setup failed");
        const auto client_bytes =
            config.tls.client_application_bytes.value_or(config.tls.application_bytes);
        const auto server_bytes =
            config.tls.server_application_bytes.value_or(config.tls.application_bytes);
        const bool application_enabled = config.tls.scenario != Scenario::Handshake;
        std::vector<std::uint8_t> outgoing(
            application_enabled ? (role == Role::Client ? client_bytes : server_bytes) : 0);
        std::vector<std::uint8_t> incoming(
            application_enabled ? (role == Role::Client ? server_bytes : client_bytes) : 0);
        std::vector<std::uint8_t> output_buffer(role == Role::Server && config.tls.scenario ==
                                                                            Scenario::FinishedPing
                                                    ? config.stream_capacity
                                                    : 0);
        info.connections.reserve(count);
        if (config.isolate)
            control::isolate(true);
        info.declaration = api.declaration(context.get());
        const auto linkage = info.declaration.build_options.find(";tls_linkage=");
        info.config.tls_linkage =
            linkage == std::string::npos
                ? "unavailable"
                : info.declaration.build_options.substr(
                      linkage + 13,
                      info.declaration.build_options.find(';', linkage + 13) - (linkage + 13));
        if (!saved.empty() && !info.declaration.context_serialization)
            throw std::runtime_error("adapter cannot restore context");
        if (std::find(info.declaration.scenarios.begin(), info.declaration.scenarios.end(),
                      config.tls.scenario) == info.declaration.scenarios.end())
            throw std::runtime_error("adapter does not support requested scenario");
        if (std::find(info.declaration.send_policies.begin(), info.declaration.send_policies.end(),
                      config.tls.send_policy) == info.declaration.send_policies.end())
            throw std::runtime_error("adapter does not support requested send policy");
        info.capabilities.heap_tracking &= info.declaration.allocator_hooks;
        capture.heap_supported = info.capabilities.heap_tracking;
        auto setup_event = [&](model::EventKind kind, model::Snapshot value) {
            if (!capture.heap_supported)
                value.heap.reset();
            model::Event event;
            event.kind = kind;
            event.call = model::Call::Setup;
            event.sequence = ++capture.sequence;
            event.snapshot = value;
            buffer.append(event);
        };
        if (!builtin) {
            setup_event(model::EventKind::ModuleBegin, module_begin);
            setup_event(model::EventKind::ModuleEnd, module_end);
        }
        setup_event(model::EventKind::SetupBegin, setup_begin);
        setup_event(model::EventKind::SetupEnd, setup_end);
        if (info.declaration.is_mock)
            info.incomplete.push_back("mock: no TLS encryption or certificate verification");
        info.failure_phase = "ready";
        if (buffer.overflowed())
            throw std::runtime_error("capture capacity exhausted during preparation");
        session.prepare(info, peer);
        info.preparation = session.status();
        if (config.phase_fd >= 0)
            (void)control::exchange_phase(config.phase_fd, sample, control::Phase::Setup,
                                          control::PhaseEdge::End, deadline);
        protocol.synchronize(control::MessageKind::Start, 0, deadline);
        info.clock_start = measure::clock_pair();

        for (std::size_t i = 0; i < count; ++i) {
            active_connection.emplace();
            auto& connection = *active_connection;
            connection.index = i;
            connection.warmup = i < config.warmups;
            client_lookup.run_connection(i, deadline);
            capture.connection = i;
            capture.sent = capture.received = capture.first_receive = 0;
            capture.call = model::Call::None;
            // Synchronize readiness before the TCP-inclusive trial starts.
            info.failure_phase = "ready";
            protocol.synchronize(control::MessageKind::TcpReady, i, deadline);
            protocol.synchronize(control::MessageKind::Start, i, deadline);
            info.failure_phase = "tcp";
            capture.event(role == Role::Client ? model::EventKind::TcpConnectBegin
                                               : model::EventKind::AcceptBegin);
            if (role == Role::Client) {
                sockets[i] = tcp::begin_connect(address);
                control::WaitSet connect_wait(sockets[i], control_fd, false);
                connect_wait.wait_data(true, deadline);
                tcp::finish_connect(sockets[i]);
            } else {
                while ((sockets[i] = tcp::try_accept(listener)) < 0)
                    accept_wait->wait_data(false, deadline);
            }
            capture.event(role == Role::Client ? model::EventKind::TcpConnectEnd
                                               : model::EventKind::AcceptEnd);
            connection.socket = transport::configure(
                sockets[i], config.tcp_nodelay, config.socket_send_buffer,
                config.socket_receive_buffer, config.kernel_timestamps, config.tx_timestamps);
            info.capabilities.kernel_timestamp_configured = connection.socket->kernel_timestamps;
            if (config.tls.framework_io && config.channel_observer &&
                connection.socket->kernel_timestamps) {
                info.kernel_receive_events_available = true;
                info.kernel_receive_events_reason.clear();
            }
            const auto local = tcp::local_endpoint(sockets[i]);
            const auto peer = tcp::peer_endpoint(sockets[i]);
            connection.local_address = local.address;
            connection.local_port = local.port;
            connection.peer_address = peer.address;
            connection.peer_port = peer.port;
            connection.tcp_start = tcp::read_tcp_info(sockets[i]);
            capture.event(model::EventKind::TcpReady);
            control::WaitSet wait_set(sockets[i], control_fd, false);
            transport::Channel channel{sockets[i], &capture,
                                       config.channel_observer ? TlsCapture::observe : nullptr};
            channel.output = output_buffer;
            channel.tx_timestamps = connection.socket->kernel_tx_timestamps;
            channel.observe_tx = TlsCapture::observe_tx;
            channel.holding = role == Role::Server && config.tls.scenario == Scenario::FinishedPing;
            channel.submit_first_write =
                channel.holding && config.tls.send_policy == SendPolicy::ServerHelloFirst;
            auto io = channel.io();
            info.failure_phase = "scenario";
            capture.call = model::Call::Open;
            capture.event(model::EventKind::OpenBegin);
            std::unique_ptr<Connection, decltype(api.close)> tls(api.open(context.get(), io),
                                                                 api.close);
            capture.event(model::EventKind::OpenEnd);
            if (!tls)
                throw std::runtime_error("adapter open failed");
            auto adapter_failure = [&](const char* operation) {
                const char* detail = api.error(tls.get());
                throw std::runtime_error(
                    std::string(operation) + ": " +
                    (detail && *detail ? detail : "adapter did not provide a diagnostic"));
            };
            if (role == Role::Client)
                connection.start_sequence = capture.sequence + 1;
            else if (!config.tls.framework_io || !config.channel_observer) {
                connection.primary_window_available = false;
                connection.primary_window_reason = "server_first_receive_not_observed";
            }
            auto application = [&](bool sending) {
                if (sending) {
                    capture.event(model::EventKind::PayloadPrepareBegin,
                                  model::Location::Framework);
                    for (std::size_t j = 0; j < outgoing.size(); ++j)
                        outgoing[j] = static_cast<std::uint8_t>((j + config.seed) % 251);
                    capture.event(model::EventKind::PayloadPrepareEnd, model::Location::Framework);
                }
                capture.event(sending ? model::EventKind::ApplicationWriteBegin
                                      : model::EventKind::ApplicationReadBegin);
                std::size_t offset = 0;
                const auto total = sending ? outgoing.size() : incoming.size();
                while (offset < total) {
                    const auto remaining = total - offset;
                    auto result = capture.invoke(
                        sending ? model::Call::AppSend : model::Call::AppRecv,
                        [&] {
                            return sending ? api.app_send(tls.get(), outgoing.data() + offset,
                                                          remaining)
                                           : api.app_recv(tls.get(), incoming.data() + offset,
                                                          remaining);
                        },
                        remaining);
                    const auto returned_sequence = capture.sequence;
                    if (result.step == Step::Failed)
                        adapter_failure(sending ? "application send failed"
                                                : "application receive failed");
                    if (result.bytes > remaining)
                        throw std::runtime_error("application returned too many bytes");
                    if (result.step == Step::WantRead || result.step == Step::WantWrite) {
                        if (result.bytes)
                            throw std::runtime_error("retry returned bytes");
                        capture.event(model::EventKind::WaitBegin);
                        wait_set.wait_data(result.step == Step::WantWrite, deadline);
                        capture.event(model::EventKind::WaitEnd);
                        continue;
                    }
                    if (!result.bytes)
                        throw std::runtime_error("application made no progress");
                    if (!sending && offset == 0)
                        capture.event(model::EventKind::ApplicationFirstByte);
                    offset += result.bytes;
                    if (offset == total)
                        connection.end_sequence = returned_sequence;
                }
                capture.event(sending ? model::EventKind::ApplicationWriteEnd
                                      : model::EventKind::ApplicationReadEnd);
                if (!sending) {
                    for (std::size_t j = 0; j < incoming.size(); ++j)
                        if (incoming[j] != static_cast<std::uint8_t>((j + config.seed) % 251))
                            throw std::runtime_error("application payload mismatch");
                }
            };
            bool ping_written = false;
            for (;;) {
                auto step = capture.invoke(model::Call::Handshake,
                                           [&] { return api.handshake_step(tls.get()); });
                if (step == Step::Complete) {
                    if (!application_enabled)
                        connection.end_sequence = capture.sequence;
                    break;
                }
                if (step == Step::Failed)
                    adapter_failure("handshake failed");
                if (step == Step::ApplicationWriteReady) {
                    if (role != Role::Server || ping_written ||
                        (config.tls.scenario != Scenario::ServerPing &&
                         config.tls.scenario != Scenario::FinishedPing))
                        throw std::runtime_error("unexpected application write readiness");
                    application(true);
                    if (channel.holding) {
                        capture.event(model::EventKind::OutputFlushBegin,
                                      model::Location::Framework);
                        channel.holding = false;
                        while (channel.queued) {
                            const auto result = capture.invoke(
                                model::Call::Flush, [&] { return channel.flush(); },
                                channel.queued - channel.submitted);
                            if (result.status == IoStatus::WantWrite) {
                                capture.event(model::EventKind::WaitBegin);
                                wait_set.wait_data(true, deadline);
                                capture.event(model::EventKind::WaitEnd);
                            } else if (result.status != IoStatus::Ok) {
                                throw std::runtime_error("output batch submission failed");
                            }
                        }
                        capture.event(model::EventKind::OutputFlushEnd, model::Location::Framework);
                    }
                    ping_written = true;
                    continue;
                }
                capture.event(model::EventKind::WaitBegin);
                wait_set.wait_data(step == Step::WantWrite, deadline);
                capture.event(model::EventKind::WaitEnd);
            }
            capture.event(model::EventKind::HandshakeComplete);
            connection.verification = capture.invoke(
                model::Call::Verification, [&] { return api.peer_verification(tls.get()); });
            if (connection.verification == Verification::Failed ||
                ((role == Role::Client || config.tls.mutual_auth) &&
                 connection.verification != Verification::Passed))
                throw std::runtime_error("peer verification did not pass");
            if (application_enabled) {
                const bool client_first = config.tls.scenario == Scenario::ClientRequest;
                const bool sender_first = (role == Role::Client) == client_first;
                if (sender_first) {
                    if (!ping_written)
                        application(true);
                    application(false);
                } else {
                    application(false);
                    application(true);
                }
                connection.application_verified = true;
            }
            connection.scenario_completed = true;
            client_lookup.scenario_end();
            if (role == Role::Server && capture.first_receive)
                connection.start_sequence = capture.first_receive;
            if (connection.start_sequence) {
                connection.primary_window_available = true;
                connection.primary_window_reason.clear();
            }
            connection.negotiated =
                capture.invoke(model::Call::Negotiated, [&] { return api.negotiated(tls.get()); });
            if (!info.declaration.is_mock) {
                const auto& n = connection.negotiated;
                if (n.version != "TLS1.3" || n.resumed || n.hello_retry_request)
                    throw std::runtime_error("not a normal full TLS 1.3 handshake");
                auto check = [&](const std::string& actual, const std::string& wanted,
                                 const char* field) {
                    if (actual.empty())
                        info.incomplete.push_back(
                            std::string("negotiated ") + field +
                            " is unobserved; requested value is not a measurement");
                    else if (actual != wanted)
                        throw std::runtime_error(std::string("negotiated ") + field +
                                                 " differs from requested profile");
                };
                check(n.cipher, config.tls.cipher, "cipher");
                check(n.group, config.tls.group, "group");
                check(n.signature, config.tls.signature, "signature");
                if ((role == Role::Client || config.tls.mutual_auth) && !n.peer_certificate_present)
                    throw std::runtime_error("required peer certificate was not observed");
            }
            connection.tcp_end = tcp::read_tcp_info(sockets[i]);
            info.connections.push_back(std::move(connection));
            active_connection.reset();
            protocol.synchronize(control::MessageKind::ConnectionComplete, i, deadline);
            capture.call = model::Call::Close;
            capture.event(model::EventKind::CloseBegin);
            channel.drain_tx();
            // Both peers have completed the scenario. This bounded diagnostic
            // drain is outside every completion window and never changes TLS validity.
            const auto drain_deadline = std::min(deadline, std::chrono::steady_clock::now() +
                                                               std::chrono::milliseconds(100));
            while (channel.tx_timestamps && channel.tx_acknowledged_end < capture.sent &&
                   !channel.tx_drain_error && std::chrono::steady_clock::now() < drain_deadline) {
                pollfd pending{sockets[i], 0, 0}; // POLLERR is always reported
                (void)::poll(&pending, 1, 1);
                channel.drain_tx();
                if (pending.revents & (POLLHUP | POLLNVAL))
                    break;
            }
            info.connections.back().socket->kernel_tx_drain_error = channel.tx_drain_error;
            tls.reset();
            capture.event(model::EventKind::CloseEnd);
            ::close(sockets[i]);
            sockets[i] = -1;
            client_lookup.close_connection(i);
        }
        if (config.phase_fd >= 0)
            (void)control::exchange_phase(config.phase_fd, sample, control::Phase::Scenario,
                                          control::PhaseEdge::End, deadline);
        auto output = api.save(context.get());
        info.saved_context_size = output.size();
        capture.call = model::Call::Save;
        capture.event(model::EventKind::Save);
        writer.write_context(output);
        capture.invoke(model::Call::Teardown, [&] {
            context.reset();
            return 0;
        });
        info.clock_end = measure::clock_pair();
        info.perf_complete = info.capabilities.perf;
        for (const auto& event : buffer.events())
            if (!event.snapshot.cycles || !event.snapshot.instructions ||
                !event.snapshot.perf_enabled || !event.snapshot.perf_running ||
                *event.snapshot.perf_running == 0 ||
                *event.snapshot.perf_running < *event.snapshot.perf_enabled)
                info.perf_complete = false;
        if (buffer.overflowed() || client_lookup.overflowed())
            throw std::runtime_error("capture buffer overflow");
    } catch (const std::exception& error) {
        record_failure(error.what());
        cleanup_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(config.flush_grace_ms);
        protocol.fail(info.invalid_reason, *cleanup_deadline);
    }
    close_all(sockets);
    client_lookup.close_sockets();
    if (!cleanup_deadline)
        cleanup_deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(config.flush_grace_ms);
    const auto flush_deadline = *cleanup_deadline;
    if (info.valid) {
        info.failure_phase = "cleanup";
        try {
            protocol.synchronize(control::MessageKind::Flush, 0, flush_deadline);
        } catch (const std::exception& error) {
            record_failure(error.what());
        }
    }
    if (info.valid)
        info.failure_phase.clear();
    try {
        writer.write(info, buffer);
        client_lookup.write(info.valid, info.invalid_reason, flush_deadline);
        if (info.valid)
            protocol.synchronize(control::MessageKind::Flushed, 0, flush_deadline);
    } catch (const std::exception& error) {
        record_failure(error.what());
        protocol.fail(info.invalid_reason, flush_deadline);
        // The process exit status and local cleanup marker retain flush failures.
        std::ofstream failure(std::filesystem::path(directory) /
                              (std::string(model::name(role)) + ".failure.json"));
        failure << nlohmann::json{{"phase", "cleanup"},
                                  {"valid", false},
                                  {"run_id", config.run_id},
                                  {"context_id", config.context_id},
                                  {"reason", info.invalid_reason}}
                << '\n';
        std::cerr << model::name(role) << " cleanup: " << error.what() << '\n';
    }
    return info.valid ? 0 : 1;
}

} // namespace turtle::lifecycle::detail
