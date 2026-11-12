#include "record/service.hpp"
#include "record/json.hpp"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <unistd.h>

namespace turtle::record {
namespace {
using Json = nlohmann::json;

template <class T> Json nullable(const std::optional<T>& value) {
    return value ? Json(*value) : Json(nullptr);
}

struct Bytes {
    explicit Bytes(std::size_t capacity) : storage(capacity) {}
    std::vector<std::uint8_t> storage;
    std::size_t used = 0;

    bool append(std::span<const std::uint8_t> data) noexcept {
        if (data.size() > storage.size() - used)
            return false;
        if (!data.empty())
            std::copy(data.begin(), data.end(), storage.begin() + used);
        used += data.size();
        return true;
    }
    std::span<const std::uint8_t> view() const noexcept {
        return {storage.data(), used};
    }
};

std::ofstream open_file(const std::string& path, std::ios::openmode mode = std::ios::trunc) {
    std::ofstream file(path, std::ios::binary | mode);
    if (!file)
        throw std::runtime_error("cannot open artifact: " + path);
    file.exceptions(std::ios::badbit | std::ios::failbit);
    return file;
}

void write_bytes(std::ofstream& file, std::span<const std::uint8_t> data) {
    if (!data.empty())
        file.write(reinterpret_cast<const char*>(data.data()),
                   static_cast<std::streamsize>(data.size()));
    file.flush();
}

const char* service_type(ServiceArtifact artifact) noexcept {
    return artifact == ServiceArtifact::CertificateLookup ? lookup_record_type : ca_record_type;
}

std::string object_id_string(std::uint64_t object_id) {
    std::ostringstream output;
    output << "fnv1a64:" << std::hex << std::nouppercase << std::setw(16) << std::setfill('0')
           << object_id;
    return output.str();
}

Json heap_json(const model::HeapSnapshot& value) {
    return {{"live", value.live},
            {"peak", value.peak},
            {"interval_peak", value.interval_peak},
            {"allocations", value.allocations},
            {"frees", value.frees},
            {"allocated_total", value.allocated_total}};
}

Json capabilities_json(const model::Capabilities& value) {
    return {{"monotonic_clock", value.monotonic_clock},
            {"thread_cpu_clock", value.thread_cpu_clock},
            {"perf", value.perf},
            {"perf_requested_scope", model::name(value.perf_requested_scope)},
            {"perf_status", model::name(value.perf_status)},
            {"perf_effective_scope", value.perf_effective_scope
                                         ? Json(model::name(*value.perf_effective_scope))
                                         : Json(nullptr)},
            {"perf_failure_stage", value.perf_failure_stage
                                       ? Json(model::name(*value.perf_failure_stage))
                                       : Json(nullptr)},
            {"perf_error_number", nullable(value.perf_error_number)},
            {"heap_tracking", value.heap_tracking},
            {"stack_tracking", value.stack_tracking},
            {"kernel_timestamp_configured", value.kernel_timestamp_configured},
            {"hardware_timestamps", value.hardware_timestamps},
            {"affinity", value.affinity},
            {"monotonic_resolution_ns", value.monotonic_resolution_ns},
            {"thread_cpu_resolution_ns", value.thread_cpu_resolution_ns},
            {"perf_note", value.perf_note},
            {"stack_note", value.stack_note},
            {"hardware_note", value.hardware_note},
            {"trace_note", value.trace_note},
            {"warnings", value.warnings}};
}

Json calibration_json(const model::Calibration& value) {
    return {{"elapsed_ns", value.elapsed_ns},
            {"cpu_ns", value.cpu_ns},
            {"cycles", value.cycles},
            {"instructions", value.instructions}};
}

Json event_json(ServiceArtifact artifact, const ServiceEvent& event) {
    const auto& snapshot = event.snapshot;
    const auto heap_domain = artifact == ServiceArtifact::CertificateLookup
                                 ? model::HeapDomain::Lookup
                                 : model::HeapDomain::MockCa;
    return {{"type", service_type(artifact)},
            {"schema", model::lookup_record_schema},
            {"record_kind", "event"},
            {"sample", event.sample},
            {"connection", event.connection},
            {"request_id", event.request_id},
            {"sequence", event.sequence},
            {"participant", model::name(event.participant)},
            {"stream_id", event.stream_id},
            {"kind", model::name(event.kind)},
            {"monotonic_ns", snapshot.monotonic_ns},
            {"thread_cpu_ns", snapshot.thread_cpu_ns},
            {"cycles", nullable(snapshot.cycles)},
            {"instructions", nullable(snapshot.instructions)},
            {"perf_enabled", nullable(snapshot.perf_enabled)},
            {"perf_running", nullable(snapshot.perf_running)},
            {"heap_domain", model::name(heap_domain)},
            {"heap", snapshot.heap ? heap_json(*snapshot.heap) : Json(nullptr)},
            {"requested", event.requested},
            {"transferred", event.transferred},
            {"result", event.result},
            {"system_error", event.system_error}};
}

} // namespace

struct ServiceBuffer::State {
    explicit State(const ServiceLimits& limits) : event_storage(limits.events) {
        if (limits.connections > std::numeric_limits<std::size_t>::max() / 2)
            throw std::length_error("too many service capture connections");
        const std::size_t stream_count = limits.connections * 2;
        if (limits.bytes_per_direction != 0 &&
            stream_count > std::numeric_limits<std::size_t>::max() / limits.bytes_per_direction)
            throw std::length_error("service byte capacity overflow");
        const std::size_t stream_bytes = stream_count * limits.bytes_per_direction;
        if (event_storage.size() >
            (std::numeric_limits<std::size_t>::max() - stream_bytes) / sizeof(ServiceEvent))
            throw std::length_error("service event capacity overflow");
        streams.reserve(limits.connections * 2);
        for (std::size_t i = 0; i < limits.connections * 2; ++i)
            streams.emplace_back(limits.bytes_per_direction);
        reserved = event_storage.size() * sizeof(ServiceEvent) + stream_bytes;
    }
    std::vector<ServiceEvent> event_storage;
    std::size_t event_count = 0;
    std::vector<Bytes> streams;
    std::size_t dropped = 0;
    std::size_t reserved = 0;

    std::size_t stream_index(std::size_t connection, model::Direction direction) const noexcept {
        if (connection >= streams.size() / 2)
            return streams.size();
        return connection * 2 + (direction == model::Direction::Received ? 1 : 0);
    }
    bool reject() noexcept {
        ++dropped;
        return false;
    }
};

ServiceBuffer::ServiceBuffer(const ServiceLimits& limits)
    : state_(std::make_unique<State>(limits)) {}
ServiceBuffer::~ServiceBuffer() = default;
bool ServiceBuffer::append(ServiceEvent event) noexcept {
    auto& state = *state_;
    if (state.event_count == state.event_storage.size())
        return state.reject();
    state.event_storage[state.event_count++] = event;
    return true;
}
bool ServiceBuffer::append_bytes(std::size_t connection, model::Direction direction,
                                 std::span<const std::uint8_t> bytes) noexcept {
    auto& state = *state_;
    const auto index = state.stream_index(connection, direction);
    if (index == state.streams.size() || !state.streams[index].append(bytes))
        return state.reject();
    return true;
}
std::span<const ServiceEvent> ServiceBuffer::events() const noexcept {
    return {state_->event_storage.data(), state_->event_count};
}
std::span<const std::uint8_t> ServiceBuffer::bytes(std::size_t connection,
                                                   model::Direction direction) const noexcept {
    const auto index = state_->stream_index(connection, direction);
    return index == state_->streams.size() ? std::span<const std::uint8_t>{}
                                           : state_->streams[index].view();
}
bool ServiceBuffer::overflowed() const noexcept {
    return state_->dropped != 0;
}
std::size_t ServiceBuffer::dropped() const noexcept {
    return state_->dropped;
}
std::size_t ServiceBuffer::reserved_bytes() const noexcept {
    return state_->reserved;
}

struct ServiceWriter::State {
    State(const std::string& directory, ServiceArtifact value, std::size_t connections,
          ServiceMetadata value_metadata)
        : artifact(value), metadata(std::move(value_metadata)),
          records(open_file(
              directory + "/" +
              (value == ServiceArtifact::CertificateLookup ? lookup_filename : ca_filename))) {
        const std::string prefix = artifact == ServiceArtifact::CertificateLookup ? "lookup" : "ca";
        streams.reserve(connections * 2);
        for (std::size_t i = 0; i < connections; ++i) {
            const std::string base = directory + "/" + prefix + "-" + std::to_string(i);
            streams.push_back(open_file(base + ".sent.bin"));
            streams.push_back(open_file(base + ".received.bin"));
        }
    }
    ServiceArtifact artifact;
    ServiceMetadata metadata;
    std::ofstream records;
    std::vector<std::ofstream> streams;
    bool written = false;
};

ServiceWriter::ServiceWriter(const std::string& directory, ServiceArtifact artifact,
                             std::size_t connections, ServiceMetadata metadata)
    : state_(std::make_unique<State>(directory, artifact, connections, std::move(metadata))) {}
ServiceWriter::~ServiceWriter() = default;
void ServiceWriter::write(std::span<const ServiceConnectionInfo> connections,
                          const ServiceBuffer& buffer, model::ArtifactStatus footer_status,
                          std::string_view incomplete_reason) {
    auto& state = *state_;
    if (state.written)
        throw std::logic_error("service artifacts already written");
    if (connections.size() != state.streams.size() / 2)
        throw std::invalid_argument("service connection count does not match preopened files");
    state.written = true;

    const auto& metadata = state.metadata;
    state.records << Json({{"type", service_type(state.artifact)},
                           {"schema", model::lookup_record_schema},
                           {"record_kind", "header"},
                           {"sample", metadata.sample},
                           {"run_id", metadata.run_id},
                           {"context_id", metadata.context_id},
                           {"clock_domain", metadata.clock_domain},
                           {"scenario_name", metadata.scenario_name},
                           {"cache_mode", model::name(metadata.cache_mode)},
                           {"cache_state_id", metadata.cache_state_id},
                           {"object_id", object_id_string(metadata.object_id)},
                           {"object_size", metadata.object_size},
                           {"initial_cache_bytes", metadata.initial_cache_bytes},
                           {"cache_capacity", metadata.cache_capacity},
                           {"reference_bytes", metadata.reference_bytes},
                           {"reference_capacity", metadata.reference_capacity},
                           {"framework_reserved_bytes", metadata.framework_reserved_bytes},
                           {"mode", model::name(metadata.mode)},
                           {"pid", metadata.pid},
                           {"capabilities", capabilities_json(metadata.capabilities)},
                           {"calibration", calibration_json(metadata.calibration)},
                           {"pinned_cpu", nullable(metadata.pinned_cpu)},
                           {"observation_level", metadata.observation_level}})
                         .dump()
                  << '\n';
    for (const auto& event : buffer.events())
        state.records << event_json(state.artifact, event).dump() << '\n';

    for (const auto& connection : connections) {
        state.records << Json({{"type", service_type(state.artifact)},
                               {"schema", model::lookup_record_schema},
                               {"record_kind", "connection_summary"},
                               {"sample", connection.sample},
                               {"connection", connection.connection},
                               {"warmup", connection.warmup},
                               {"request_id", connection.request_id},
                               {"participant", model::name(connection.participant)},
                               {"stream_id", connection.stream_id},
                               {"object_id", object_id_string(connection.object_id)},
                               {"object_size", connection.object_size},
                               {"cache_hit", connection.cache_hit},
                               {"request_count", connection.request_count},
                               {"heap_domain", model::name(connection.memory.domain)},
                               {"heap", connection.memory.heap ? heap_json(*connection.memory.heap)
                                                               : Json(nullptr)},
                               {"logical_cache_bytes", connection.memory.logical_cache_bytes},
                               {"cache_capacity", connection.memory.cache_capacity},
                               {"reference_bytes", connection.memory.reference_bytes},
                               {"framework_reserved_bytes",
                                connection.memory.framework_reserved_bytes},
                               {"tcp_start", detail::tcp_json(connection.tcp_start)},
                               {"tcp_end", detail::tcp_json(connection.tcp_end)},
                               {"artifact_status", model::name(connection.artifact_status)},
                               {"incomplete_reason", connection.incomplete_reason}})
                             .dump()
                      << '\n';
    }

    std::string reason(incomplete_reason);
    if (footer_status == model::ArtifactStatus::Complete &&
        std::any_of(connections.begin(), connections.end(), [](const auto& connection) {
            return connection.artifact_status != model::ArtifactStatus::Complete;
        })) {
        footer_status = model::ArtifactStatus::Partial;
        if (!reason.empty())
            reason += "; ";
        reason += "connection artifact incomplete";
    }
    if (buffer.overflowed()) {
        if (!reason.empty())
            reason += "; ";
        reason += "capture capacity exceeded";
        if (footer_status == model::ArtifactStatus::Complete)
            footer_status = model::ArtifactStatus::Partial;
    }
    for (std::size_t i = 0; i < state.streams.size(); ++i)
        write_bytes(state.streams[i], buffer.bytes(i / 2, i % 2 == 0 ? model::Direction::Sent
                                                                     : model::Direction::Received));
    state.records << Json({{"type", service_type(state.artifact)},
                           {"schema", model::lookup_record_schema},
                           {"record_kind", "footer"},
                           {"sample", metadata.sample},
                           {"run_id", metadata.run_id},
                           {"context_id", metadata.context_id},
                           {"clock_domain", metadata.clock_domain},
                           {"artifact_status", model::name(footer_status)},
                           {"incomplete_reason", reason},
                           {"capture_dropped", buffer.dropped()}})
                         .dump()
                  << '\n';
    state.records.flush();
}

} // namespace turtle::record
