#include "lifecycle/lookup_runtime.hpp"
#include "model/run_config.hpp"
#include "model/sample.hpp"
#include "model/service.hpp"
#include "record/service.hpp"

#include "capability/capability.hpp"
#include "transport/channel.hpp"
#include "transport/tcp.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <unistd.h>

namespace turtle::lifecycle::detail {
namespace {

struct ServiceCapture {
    measure::Meter& meter;
    record::ServiceBuffer& buffer;
    model::ParticipantKind participant;
    std::uint64_t sample = 0;
    std::size_t connection = 0;
    std::uint64_t sequence = 0;
    std::uint64_t sent = 0;
    std::uint64_t received = 0;
    std::string_view stream_id;
    measure::HeapTracker* heap_tracker = nullptr;

    model::Snapshot snapshot() noexcept {
        auto value = meter.read(false);
        if (heap_tracker)
            value.heap = heap_tracker->read(false);
        return value;
    }

    void append(model::ServiceEventKind kind, std::uint64_t request_id = 0,
                std::size_t requested = 0, std::size_t transferred = 0, std::int64_t result = 0,
                int system_error = 0) noexcept {
        record::ServiceEvent event;
        event.kind = kind;
        event.sample = sample;
        event.connection = connection;
        event.request_id = request_id;
        event.sequence = ++sequence;
        event.participant = participant;
        event.stream_id = stream_id;
        event.snapshot = snapshot();
        event.requested = requested;
        event.transferred = transferred;
        event.result = result;
        event.system_error = system_error;
        buffer.append(event);
    }

    static void semantic(void* opaque, const lookup::Observation& observation) noexcept {
        auto& self = *static_cast<ServiceCapture*>(opaque);
        model::ServiceEventKind kind = model::ServiceEventKind::CacheLookup;
        switch (observation.kind) {
        case lookup::SemanticEventKind::CacheLookup:
            kind = model::ServiceEventKind::CacheLookup;
            break;
        case lookup::SemanticEventKind::CacheHit:
            kind = model::ServiceEventKind::CacheHit;
            break;
        case lookup::SemanticEventKind::CacheMiss:
            kind = model::ServiceEventKind::CacheMiss;
            break;
        case lookup::SemanticEventKind::CacheInsert:
            kind = model::ServiceEventKind::CacheInsert;
            break;
        case lookup::SemanticEventKind::RequestBegin:
            kind = model::ServiceEventKind::RequestBegin;
            break;
        case lookup::SemanticEventKind::ResponseComplete:
            kind = model::ServiceEventKind::ResponseComplete;
            break;
        case lookup::SemanticEventKind::UsableObject:
            kind = model::ServiceEventKind::UsableObject;
            break;
        case lookup::SemanticEventKind::CaProcessBegin:
            kind = model::ServiceEventKind::CaProcessBegin;
            break;
        case lookup::SemanticEventKind::CaProcessEnd:
            kind = model::ServiceEventKind::CaProcessEnd;
            break;
        }
        self.append(kind, observation.request_id, observation.requested, observation.transferred,
                    static_cast<std::int64_t>(observation.io_status), observation.system_error);
    }

    static void io(void* opaque, const transport::Observation& observation) noexcept {
        auto& self = *static_cast<ServiceCapture*>(opaque);
        const auto kind = observation.sending
                              ? (observation.entering ? model::ServiceEventKind::IoSendEnter
                                                      : model::ServiceEventKind::IoSendReturn)
                              : (observation.entering ? model::ServiceEventKind::IoRecvEnter
                                                      : model::ServiceEventKind::IoRecvReturn);
        self.append(kind, lookup::single_request_id, observation.requested,
                    observation.entering ? 0 : observation.result.bytes,
                    observation.entering ? 0 : static_cast<std::int64_t>(observation.result.status),
                    observation.entering ? 0 : observation.result.system_error);
        if (!observation.entering && observation.result.bytes) {
            self.buffer.append_bytes(self.connection,
                                     observation.sending ? model::Direction::Sent
                                                         : model::Direction::Received,
                                     {observation.data, observation.result.bytes});
            (observation.sending ? self.sent : self.received) += observation.result.bytes;
        }
    }
};

std::vector<std::uint8_t> read_bytes(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error("lookup object input unavailable: " + path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::vector<std::uint8_t> decode_snapshot(const std::string& path,
                                          std::span<const std::uint8_t> expected) {
    std::ifstream input(path);
    if (!input)
        throw std::runtime_error("lookup snapshot input unavailable: " + path);
    nlohmann::json document;
    try {
        input >> document;
    } catch (const nlohmann::json::exception&) {
        throw std::runtime_error("lookup snapshot is not valid JSON");
    }
    const std::array<const char*, 5> keys{"type", "schema", "object_id", "object_size",
                                          "object_hex"};
    if (!document.is_object() || document.size() != keys.size())
        throw std::runtime_error("lookup snapshot fields differ from schema 1");
    for (const char* key : keys)
        if (!document.contains(key))
            throw std::runtime_error("lookup snapshot field is missing");
    if (!document["type"].is_string() ||
        document["type"].get<std::string>() != lookup::snapshot_type ||
        !document["schema"].is_number_unsigned() ||
        document["schema"].get<unsigned>() != lookup::snapshot_schema ||
        !document["object_id"].is_string() || !document["object_size"].is_number_unsigned() ||
        !document["object_hex"].is_string())
        throw std::runtime_error("lookup snapshot field type or value is invalid");
    const auto& encoded = document["object_hex"].get_ref<const std::string&>();
    if (encoded.size() % 2)
        throw std::runtime_error("lookup snapshot object_hex is malformed");
    std::vector<std::uint8_t> bytes;
    bytes.reserve(encoded.size() / 2);
    auto nibble = [](char value) -> int {
        if (value >= '0' && value <= '9')
            return value - '0';
        if (value >= 'a' && value <= 'f')
            return value - 'a' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < encoded.size(); i += 2) {
        const int high = nibble(encoded[i]), low = nibble(encoded[i + 1]);
        if (high < 0 || low < 0)
            throw std::runtime_error("lookup snapshot object_hex must be lowercase hexadecimal");
        bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    if (bytes.empty() || bytes.size() != document["object_size"].get<std::size_t>() ||
        document["object_id"].get<std::string>() != model::fingerprint(bytes) ||
        bytes.size() != expected.size() ||
        !std::equal(bytes.begin(), bytes.end(), expected.begin()))
        throw std::runtime_error("lookup snapshot does not match the reference object");
    return bytes;
}

} // namespace

struct ClientLookupRuntime::Impl {
    // Declaration order is a lifetime contract: allocator-backed cache/client payloads
    // are destroyed before their HeapTracker, and stream-id strings outlive capture.
    std::unique_ptr<measure::HeapTracker> heap;
    std::unique_ptr<lookup::Cache> cache;
    std::unique_ptr<record::ServiceBuffer> buffer;
    std::vector<record::ServiceConnectionInfo> connections;
    std::unique_ptr<ServiceCapture> capture;
    std::unique_ptr<record::ServiceWriter> writer;
    std::vector<std::unique_ptr<control::WaitSet>> wait_sets;
    std::vector<std::unique_ptr<lookup::Client>> clients;
};

LookupInputs load_lookup_inputs(const model::RunConfig& config) {
    LookupInputs result;
    if (!config.lookup.enabled)
        return result;
    auto object = read_bytes(config.lookup.object_file);
    result.reference = std::make_unique<lookup::Snapshot>(object);
    if (config.lookup.cache_mode == model::CacheMode::FixedSnapshot)
        result.initial = std::make_unique<lookup::Snapshot>(
            decode_snapshot(config.lookup.snapshot_file, object));
    else
        result.initial = std::make_unique<lookup::Snapshot>();
    return result;
}

ClientLookupRuntime::ClientLookupRuntime(const model::RunConfig& config, measure::Meter& meter,
                                         std::uint64_t sample, const std::string& directory,
                                         const lookup::Snapshot* reference,
                                         const lookup::Snapshot* initial) noexcept
    : config_(config), meter_(meter), sample_(sample), directory_(directory), reference_(reference),
      initial_(initial) {}

ClientLookupRuntime::~ClientLookupRuntime() {
    close_all(sockets_);
    if (service_fd_ >= 0)
        ::close(service_fd_);
}

bool ClientLookupRuntime::enabled() const noexcept {
    return reference_ != nullptr;
}

void ClientLookupRuntime::prepare(model::SampleInfo& info, control::Deadline deadline) {
    if (!enabled())
        return;
    const std::size_t count = config_.warmups + config_.connections;
    service_fd_ = tcp::begin_connect(tcp::prepare_dial(
        config_.lookup.source_address, {config_.lookup.address, config_.lookup.control_port}));
    control::wait(service_fd_, true, deadline);
    tcp::finish_connect(service_fd_);
    service_ = std::make_unique<control::Waiter>(service_fd_);
    auto identity = config_;
    negotiate(*service_, identity, deadline);
    protocol_ = std::make_unique<PeerProtocol>(*service_, sample_);
    for (std::size_t i = 0; i < count; ++i) {
        const auto fd = tcp::begin_connect(tcp::prepare_dial(
            config_.lookup.source_address, {config_.lookup.address, config_.lookup.port}));
        sockets_.push_back(fd);
        control::wait(fd, true, deadline);
        tcp::finish_connect(fd);
    }
    impl_ = std::make_unique<Impl>();
    bool lookup_timestamps = true;
    impl_->wait_sets.reserve(count);
    for (int fd : sockets_) {
        const auto settings =
            transport::configure(fd, config_.tcp_nodelay, config_.socket_send_buffer,
                                 config_.socket_receive_buffer, config_.kernel_timestamps);
        lookup_timestamps = lookup_timestamps && settings.kernel_timestamps;
        impl_->wait_sets.push_back(std::make_unique<control::WaitSet>(fd, service_fd_, false));
        if (auto reason = tcp::check_ready(fd); !reason.empty())
            throw std::runtime_error(reason);
    }
    impl_->heap = std::make_unique<measure::HeapTracker>(config_.mode == model::Mode::Memory);
    impl_->cache = std::make_unique<lookup::Cache>(impl_->heap->allocator());
    impl_->buffer = std::make_unique<record::ServiceBuffer>(
        record::ServiceLimits{config_.event_capacity, config_.stream_capacity, count});
    impl_->capture =
        std::make_unique<ServiceCapture>(ServiceCapture{meter_,
                                                        *impl_->buffer,
                                                        model::ParticipantKind::TlsClient,
                                                        sample_,
                                                        0,
                                                        0,
                                                        0,
                                                        0,
                                                        {},
                                                        impl_->heap.get()});
    impl_->connections.resize(count);
    impl_->clients.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        auto& connection = impl_->connections[i];
        connection.sample = sample_;
        connection.connection = i;
        connection.warmup = i < config_.warmups;
        connection.request_id = lookup::single_request_id;
        connection.participant = model::ParticipantKind::TlsClient;
        connection.object_id = reference_->object().id;
        connection.object_size = reference_->object().bytes.size();
        connection.stream_id = "lookup-" + std::to_string(i);
        impl_->clients.push_back(std::make_unique<lookup::Client>(
            *impl_->cache, reference_->object(), impl_->heap->allocator(),
            lookup::Observer{impl_->capture.get(), ServiceCapture::semantic}));
    }
    record::ServiceMetadata metadata;
    metadata.sample = sample_;
    metadata.run_id = config_.run_id;
    metadata.context_id = config_.context_id;
    metadata.clock_domain = config_.clock_domain;
    metadata.cache_mode = config_.lookup.cache_mode;
    metadata.cache_state_id =
        initial_ && !initial_->empty() ? model::fingerprint(initial_->object().bytes) : "empty";
    metadata.object_id = reference_->object().id;
    metadata.object_size = reference_->object().bytes.size();
    metadata.cache_capacity = impl_->cache->capacity();
    metadata.initial_cache_bytes = initial_->empty() ? 0 : initial_->object().bytes.size();
    metadata.reference_bytes = reference_->object().bytes.size();
    metadata.reference_capacity = reference_->capacity();
    metadata.framework_reserved_bytes =
        impl_->cache->fixed_reserved_bytes() + impl_->buffer->reserved_bytes();
    for (const auto& client : impl_->clients)
        metadata.framework_reserved_bytes += client->fixed_reserved_bytes();
    metadata.mode = config_.mode;
    metadata.pid = ::getpid();
    metadata.capabilities = info.capabilities;
    metadata.capabilities.kernel_timestamp_configured = !sockets_.empty() && lookup_timestamps;
    metadata.calibration = info.calibration;
    if (info.pinned_cpu >= 0)
        metadata.pinned_cpu = info.pinned_cpu;
    impl_->writer = std::make_unique<record::ServiceWriter>(
        directory_, record::ServiceArtifact::CertificateLookup, count, std::move(metadata));
    protocol_->synchronize(control::MessageKind::TcpReady, 0, deadline);
    protocol_->synchronize(control::MessageKind::Start, 0, deadline);
}

void ClientLookupRuntime::run_connection(std::size_t index, control::Deadline deadline) {
    if (!enabled())
        return;
    protocol_->synchronize(control::MessageKind::Start, index, deadline);
    impl_->cache->restore(*initial_);
    auto& connection = impl_->connections[index];
    impl_->capture->connection = index;
    impl_->capture->stream_id = connection.stream_id;
    impl_->capture->sent = impl_->capture->received = 0;
    impl_->capture->append(model::ServiceEventKind::ScenarioBegin, lookup::single_request_id);
    transport::Channel channel{sockets_[index], impl_->capture.get(), ServiceCapture::io};
    auto io = channel.io();
    connection.tcp_start = tcp::read_tcp_info(sockets_[index]);
    auto& client = *impl_->clients[index];
    client.begin(sample_, index);
    for (;;) {
        const auto progress = client.advance(io);
        if (progress == lookup::Progress::Complete)
            break;
        if (progress == lookup::Progress::Failed)
            throw std::runtime_error("certificate lookup failed: " + std::string(client.error()));
        impl_->capture->append(model::ServiceEventKind::WaitBegin, lookup::single_request_id);
        impl_->wait_sets[index]->wait_data(progress == lookup::Progress::WantWrite, deadline);
        impl_->capture->append(model::ServiceEventKind::WaitEnd, lookup::single_request_id);
    }
    control::Message completion;
    completion.kind = client.cache_hit() ? control::MessageKind::LookupSkipped
                                         : control::MessageKind::ResponseComplete;
    completion.sample = sample_;
    completion.connection = index;
    control::send_message(*service_, completion, deadline);
    protocol_->synchronize(control::MessageKind::ConnectionComplete, index, deadline);
    if (client.object().bytes.size() != reference_->object().bytes.size() ||
        !std::equal(client.object().bytes.begin(), client.object().bytes.end(),
                    reference_->object().bytes.begin()))
        throw std::runtime_error("lookup usable object differs from reference");
    connection.cache_hit = client.cache_hit();
    connection.request_count = client.cache_hit() ? 0 : 1;
    connection.memory.domain = model::HeapDomain::Lookup;
    connection.memory.heap = impl_->heap->read(false);
    connection.memory.logical_cache_bytes = impl_->cache->logical_bytes();
    connection.memory.cache_capacity = impl_->cache->capacity();
    connection.memory.reference_bytes = reference_->object().bytes.size();
    connection.memory.framework_reserved_bytes =
        impl_->cache->fixed_reserved_bytes() + client.fixed_reserved_bytes();
    connection.tcp_end = tcp::read_tcp_info(sockets_[index]);
    connection.artifact_status = model::ArtifactStatus::Complete;
}

void ClientLookupRuntime::scenario_end() noexcept {
    if (impl_ && impl_->capture)
        impl_->capture->append(model::ServiceEventKind::ScenarioEnd, lookup::single_request_id);
}

void ClientLookupRuntime::mark_partial(std::size_t index, std::string_view reason) {
    if (!impl_ || !impl_->writer)
        return;
    scenario_end();
    impl_->connections[index].tcp_end = tcp::read_tcp_info(sockets_[index]);
    impl_->connections[index].artifact_status = model::ArtifactStatus::Partial;
    impl_->connections[index].incomplete_reason = reason;
}

bool ClientLookupRuntime::overflowed() const noexcept {
    return impl_ && impl_->buffer && impl_->buffer->overflowed();
}

void ClientLookupRuntime::close_connection(std::size_t index) noexcept {
    if (!enabled() || sockets_[index] < 0)
        return;
    ::close(sockets_[index]);
    sockets_[index] = -1;
}

void ClientLookupRuntime::close_sockets() noexcept {
    close_all(sockets_);
}

void ClientLookupRuntime::write(bool valid, std::string_view failure, control::Deadline cleanup) {
    if (protocol_) {
        if (valid)
            protocol_->synchronize(control::MessageKind::Flush, 0, cleanup);
        else
            protocol_->fail(std::string(failure), cleanup);
    }
    if (impl_ && impl_->writer)
        impl_->writer->write(
            impl_->connections, *impl_->buffer,
            valid ? model::ArtifactStatus::Complete : model::ArtifactStatus::Partial, failure);
}

int ca_endpoint(const model::RunConfig& config, std::uint64_t sample, const std::string& directory,
                std::vector<int> sockets, int control_fd, control::Deadline deadline,
                const lookup::Snapshot& reference) {
    const std::size_t count = sockets.size();
    control::Waiter parent(control_fd);
    PeerProtocol protocol(parent, sample);
    measure::Meter meter(config.mode, config.perf, config.perf_scope);
    record::ServiceBuffer buffer({config.event_capacity, config.stream_capacity, count});
    ServiceCapture capture{meter, buffer, model::ParticipantKind::MockCa, sample, 0, 0, 0, 0,
                           {},    nullptr};
    std::vector<record::ServiceConnectionInfo> connections(count);
    std::vector<std::unique_ptr<lookup::Responder>> responders;
    responders.reserve(count);
    if (config.pin_cores) {
        std::string reason;
        if (!capability::pin_to_cpu(config.cpu, reason))
            throw std::runtime_error("CA CPU affinity failed: " + reason);
    }
    auto capabilities = meter.capabilities();
    if (config.pin_cores)
        capabilities.affinity = true;
    std::vector<std::unique_ptr<control::WaitSet>> wait_sets;
    wait_sets.reserve(count);
    bool all_timestamps = true;
    for (int fd : sockets) {
        const auto settings =
            transport::configure(fd, config.tcp_nodelay, config.socket_send_buffer,
                                 config.socket_receive_buffer, config.kernel_timestamps);
        all_timestamps = all_timestamps && settings.kernel_timestamps;
        if (auto reason = tcp::check_ready(fd); !reason.empty())
            throw std::runtime_error(reason);
        wait_sets.push_back(std::make_unique<control::WaitSet>(fd, control_fd));
    }
    capabilities.kernel_timestamp_configured = !sockets.empty() && all_timestamps;
    auto calibration = meter.calibrate(config.calibration_samples);
    for (std::size_t i = 0; i < count; ++i) {
        connections[i].sample = sample;
        connections[i].connection = i;
        connections[i].warmup = i < config.warmups;
        connections[i].request_id = lookup::single_request_id;
        connections[i].participant = model::ParticipantKind::MockCa;
        connections[i].object_id = reference.object().id;
        connections[i].object_size = reference.object().bytes.size();
        connections[i].stream_id = "ca-" + std::to_string(i);
        responders.push_back(std::make_unique<lookup::Responder>(
            reference.object(), meter.allocator(),
            lookup::Observer{&capture, ServiceCapture::semantic}));
    }
    record::ServiceMetadata metadata;
    metadata.sample = sample;
    metadata.run_id = config.run_id;
    metadata.context_id = config.context_id;
    metadata.clock_domain = config.clock_domain;
    metadata.cache_mode = config.lookup.cache_mode;
    metadata.cache_state_id = "repository";
    metadata.object_id = reference.object().id;
    metadata.object_size = reference.object().bytes.size();
    metadata.initial_cache_bytes = 0;
    metadata.reference_bytes = reference.object().bytes.size();
    metadata.reference_capacity = reference.capacity();
    metadata.mode = config.mode;
    metadata.pid = ::getpid();
    metadata.capabilities = capabilities;
    metadata.calibration = calibration;
    metadata.framework_reserved_bytes = buffer.reserved_bytes();
    for (const auto& responder : responders)
        metadata.framework_reserved_bytes += responder->fixed_reserved_bytes();
    if (config.pin_cores)
        metadata.pinned_cpu = config.cpu;
    record::ServiceWriter writer(directory, record::ServiceArtifact::MockCa, count,
                                 std::move(metadata));
    bool valid = true;
    std::string failure;
    std::optional<std::size_t> active_connection;
    try {
        meter.require_requested_scope();
        if (config.isolate)
            control::isolate();
        protocol.synchronize(control::MessageKind::TcpReady, 0, deadline);
        protocol.synchronize(control::MessageKind::Start, 0, deadline);
        for (std::size_t i = 0; i < count; ++i) {
            protocol.synchronize(control::MessageKind::Start, i, deadline);
            active_connection = i;
            capture.connection = i;
            capture.stream_id = connections[i].stream_id;
            capture.sent = capture.received = 0;
            capture.append(model::ServiceEventKind::ScenarioBegin, lookup::single_request_id);
            connections[i].tcp_start = tcp::read_tcp_info(sockets[i]);
            transport::Channel channel{sockets[i], &capture, ServiceCapture::io};
            auto io = channel.io();
            auto& responder = *responders[i];
            responder.begin(sample, i);
            auto& waits = *wait_sets[i];
            bool skipped = false;
            for (;;) {
                const auto progress = responder.advance(io);
                if (progress == lookup::Progress::Complete)
                    break;
                if (progress == lookup::Progress::Failed)
                    throw std::runtime_error("CA response failed: " +
                                             std::string(responder.error()));
                capture.append(model::ServiceEventKind::WaitBegin, lookup::single_request_id);
                const auto ready = waits.wait(progress == lookup::Progress::WantWrite, deadline);
                capture.append(model::ServiceEventKind::WaitEnd, lookup::single_request_id);
                if (ready == control::WaitSet::Ready::Control) {
                    const auto message = control::receive_message(parent, deadline);
                    if (message.kind != control::MessageKind::LookupSkipped ||
                        message.connection != i)
                        throw std::runtime_error("CA received unexpected control message");
                    responder.abandon();
                    skipped = true;
                    break;
                }
            }
            if (!skipped) {
                const auto message = control::receive_message(parent, deadline);
                if (message.kind != control::MessageKind::ResponseComplete ||
                    message.connection != i)
                    throw std::runtime_error("CA final snapshot preceded RESPONSE_COMPLETE");
            }
            connections[i].cache_hit = skipped;
            connections[i].request_count = skipped ? 0 : 1;
            connections[i].memory.domain = model::HeapDomain::MockCa;
            connections[i].memory.heap = meter.read(false).heap;
            connections[i].memory.reference_bytes = reference.object().bytes.size();
            connections[i].memory.framework_reserved_bytes = responder.fixed_reserved_bytes();
            connections[i].tcp_end = tcp::read_tcp_info(sockets[i]);
            capture.append(model::ServiceEventKind::ScenarioEnd, lookup::single_request_id);
            connections[i].artifact_status = model::ArtifactStatus::Complete;
            active_connection.reset();
            protocol.synchronize(control::MessageKind::ConnectionComplete, i, deadline);
            ::close(sockets[i]);
            sockets[i] = -1;
        }
        if (buffer.overflowed())
            throw std::runtime_error("CA capture buffer overflow");
    } catch (const std::exception& error) {
        if (active_connection) {
            connections[*active_connection].tcp_end =
                tcp::read_tcp_info(sockets[*active_connection]);
            connections[*active_connection].artifact_status = model::ArtifactStatus::Partial;
            connections[*active_connection].incomplete_reason = error.what();
            capture.append(model::ServiceEventKind::ScenarioEnd, lookup::single_request_id);
            active_connection.reset();
        }
        valid = false;
        failure = error.what();
        protocol.fail(failure, std::chrono::steady_clock::now() +
                                   std::chrono::milliseconds(config.flush_grace_ms));
    }
    close_all(sockets);
    try {
        if (valid)
            protocol.synchronize(control::MessageKind::Flush, 0, deadline);
    } catch (const std::exception& error) {
        valid = false;
        failure = error.what();
    }
    writer.write(connections, buffer,
                 valid ? model::ArtifactStatus::Complete : model::ArtifactStatus::Partial, failure);
    return valid ? 0 : 1;
}

int run_lookup_service(model::RunConfig config) {
    if (config.clock_domain.empty()) {
        std::ifstream boot("/proc/sys/kernel/random/boot_id");
        std::getline(boot, config.clock_domain);
        config.clock_domain = "linux-boot:" + config.clock_domain;
    }
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(config.timeout_ms);
    const auto input = load_lookup_inputs(config);
    if (!input.reference)
        throw std::runtime_error("lookup service requires a local object");
    capability::choose_cpus(config, capability::inspect_environment());
    std::filesystem::create_directories(config.output_directory);
    if (std::filesystem::exists(std::filesystem::path(config.output_directory) / "ca.jsonl"))
        throw std::runtime_error("lookup output already exists");
    std::vector<int> owned;
    try {
        const auto data = tcp::listen_ipv4(config.address, config.port);
        owned.push_back(data.fd);
        const auto control = tcp::listen_ipv4(config.control_address, config.control_port);
        owned.push_back(control.fd);
        tcp::nonblocking_listener(data.fd);
        tcp::nonblocking_listener(control.fd);
        if (!config.ready_file.empty()) {
            std::ofstream ready(config.ready_file);
            ready << nlohmann::json{{"port", data.port}, {"control_port", control.port}} << '\n';
        }
        int peer;
        while ((peer = tcp::try_accept(control.fd)) < 0)
            control::wait(control.fd, false, deadline);
        owned.push_back(peer);
        control::Waiter waiter(peer);
        negotiate(waiter, config, deadline);
        std::vector<int> sockets;
        for (std::size_t i = 0; i < config.connections + config.warmups; ++i) {
            int fd;
            while ((fd = tcp::try_accept(data.fd)) < 0)
                control::wait(data.fd, false, deadline);
            sockets.push_back(fd);
            owned.push_back(fd);
        }
        // ca_endpoint owns the connected data sockets from this point.
        owned.resize(3);
        const auto result = ca_endpoint(config, config.sample, config.output_directory,
                                        std::move(sockets), peer, deadline, *input.reference);
        close_all(owned);
        return result;
    } catch (...) {
        close_all(owned);
        throw;
    }
}
} // namespace turtle::lifecycle::detail
