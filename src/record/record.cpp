#include "record/record.hpp"
#include "record/json.hpp"

#include <algorithm>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <vector>

#include <nlohmann/json.hpp>

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
    bool fits(std::size_t n) const noexcept {
        return n <= storage.size() - used;
    }
    bool append(std::span<const std::uint8_t> data) noexcept {
        if (!fits(data.size()))
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
std::span<const std::uint8_t> as_bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}
std::ofstream open_file(const std::string& path) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
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
Json tls_json(const TlsConfig& v) {
    return {{"cipher", v.cipher},
            {"group", v.group},
            {"signature", v.signature},
            {"server_name", v.server_name},
            {"ca_file", v.ca_file},
            {"server_certificate", v.server_certificate},
            {"server_key", v.server_key},
            {"client_certificate", v.client_certificate},
            {"client_key", v.client_key},
            {"mutual_auth", v.mutual_auth},
            {"compatibility_ccs", v.compatibility_ccs},
            {"framework_io", v.framework_io},
            {"tickets", v.tickets},
            {"application_bytes", v.application_bytes},
            {"record_size_limit", v.record_size_limit},
            {"certificate_compression", v.certificate_compression}};
}
Json lookup_json(const model::LookupConfig& value) {
    return {{"enabled", value.enabled},
            {"cache_mode", model::name(value.cache_mode)},
            {"object_file", value.object_file.empty() ? Json(nullptr) : Json(value.object_file)},
            {"snapshot_file",
             value.snapshot_file.empty() ? Json(nullptr) : Json(value.snapshot_file)}};
}
Json network_handoff_json(const std::optional<model::NetworkHandoff>& value) {
    if (!value)
        return nullptr;
    return {{"provenance_file", value->provenance_file},
            {"observations_file", value->observations_file},
            {"net_profile", value->net_profile_document.empty()
                                ? Json(nullptr)
                                : Json::parse(value->net_profile_document)}};
}
Json config_json(const model::RunConfig& v) {
    return {{"client_adapter", v.client_adapter},
            {"server_adapter", v.server_adapter},
            {"adapter_directory", v.adapter_directory},
            {"output_directory", v.output_directory},
            {"profile_name", v.profile_name},
            {"profile_hash", v.profile_hash},
            {"profile_document", v.profile_document},
            {"context_directory", v.context_directory},
            {"samples", v.samples},
            {"warmups", v.warmups},
            {"connections", v.connections},
            {"batch", v.batch},
            {"seed", v.seed},
            {"timeout_ms", v.timeout_ms},
            {"flush_grace_ms", v.flush_grace_ms},
            {"failure_policy", model::name(v.failure_policy)},
            {"scenario_name",
             v.lookup.enabled ? model::lookup_scenario_name : "standard-tls"},
            {"lookup", lookup_json(v.lookup)},
            {"network_manifest",
             v.network_manifest.empty() ? Json(nullptr) : Json(v.network_manifest)},
            {"network_handoff", network_handoff_json(v.network_handoff)},
            {"event_capacity", v.event_capacity},
            {"stream_capacity", v.stream_capacity},
            {"keylog_capacity", v.keylog_capacity},
            {"calibration_samples", v.calibration_samples},
            {"tcp_nodelay", v.tcp_nodelay},
            {"socket_send_buffer", v.socket_send_buffer},
            {"socket_receive_buffer", v.socket_receive_buffer},
            {"kernel_timestamps", v.kernel_timestamps},
            {"perf", v.perf},
            {"isolate", v.isolate},
            {"pin_cores", v.pin_cores},
            {"director_cpu", v.director_cpu},
            {"client_cpu", v.client_cpu},
            {"server_cpu", v.server_cpu},
            {"ca_cpu", v.ca_cpu},
            {"tls", tls_json(v.tls)},
            {"mode", model::name(v.mode)}};
}
Json declaration_json(const Declaration& v) {
    return {{"library", v.library},
            {"version", v.version},
            {"build_options", v.build_options},
            {"context_description", v.context_description},
            {"callback_io", v.callback_io},
            {"allocator_hooks", v.allocator_hooks},
            {"key_log", v.key_log},
            {"plaintext_hook", v.plaintext_hook},
            {"extra_threads", v.extra_threads},
            {"context_serialization", v.context_serialization},
            {"is_mock", v.is_mock},
            {"memory_note", v.memory_note}};
}
Json environment_json(const model::Environment& v) {
    return {{"kernel", v.kernel},
            {"cpu_model", v.cpu_model},
            {"compiler", v.compiler},
            {"governor", v.governor},
            {"boost", v.boost},
            {"environment_hash", v.environment_hash},
            {"wsl", v.wsl},
            {"allowed_cpus", v.allowed_cpus},
            {"physical_cpus", v.physical_cpus},
            {"load_before", v.load_before},
            {"warnings", v.warnings}};
}
Json capabilities_json(const model::Capabilities& v) {
    return {{"monotonic_clock", v.monotonic_clock},
            {"thread_cpu_clock", v.thread_cpu_clock},
            {"perf", v.perf},
            {"heap_tracking", v.heap_tracking},
            {"stack_tracking", v.stack_tracking},
            {"kernel_timestamp_configured", v.kernel_timestamp_configured},
            {"hardware_timestamps", v.hardware_timestamps},
            {"affinity", v.affinity},
            {"monotonic_resolution_ns", v.monotonic_resolution_ns},
            {"thread_cpu_resolution_ns", v.thread_cpu_resolution_ns},
            {"perf_note", v.perf_note},
            {"stack_note", v.stack_note},
            {"hardware_note", v.hardware_note},
            {"trace_note", v.trace_note},
            {"warnings", v.warnings}};
}
Json calibration_json(const model::Calibration& v) {
    return {{"elapsed_ns", v.elapsed_ns},
            {"cpu_ns", v.cpu_ns},
            {"cycles", v.cycles},
            {"instructions", v.instructions}};
}
Json clock_json(const model::ClockPair& v) {
    return {{"monotonic_before_ns", v.monotonic_before_ns},
            {"realtime_ns", v.realtime_ns},
            {"monotonic_after_ns", v.monotonic_after_ns}};
}
Json negotiated_json(const Negotiated& v) {
    return {{"version", v.version},
            {"cipher", v.cipher},
            {"group", v.group},
            {"signature", v.signature},
            {"resumed", v.resumed},
            {"hello_retry_request", v.hello_retry_request},
            {"peer_certificate_present", v.peer_certificate_present}};
}
Json heap_json(const model::HeapSnapshot& v) {
    return {{"live", v.live},
            {"peak", v.peak},
            {"interval_peak", v.interval_peak},
            {"allocations", v.allocations},
            {"frees", v.frees},
            {"allocated_total", v.allocated_total}};
}
Json socket_json(const std::optional<model::SocketSettings>& v) {
    if (!v)
        return nullptr;
    return {{"nonblocking", v->nonblocking},
            {"tcp_nodelay", v->tcp_nodelay},
            {"send_buffer", v->send_buffer},
            {"receive_buffer", v->receive_buffer},
            {"kernel_timestamps", v->kernel_timestamps}};
}
Json sample_json(const model::SampleInfo& v, const Buffer& buffer) {
    Json connections = Json::array();
    for (const auto& c : v.connections) {
        connections.push_back({{"index", c.index},
                               {"warmup", c.warmup},
                               {"verification", model::name(c.verification)},
                               {"negotiated", negotiated_json(c.negotiated)},
                               {"application_verified", c.application_verified},
                               {"start_sequence", c.start_sequence},
                               {"end_sequence", c.end_sequence},
                               {"socket", socket_json(c.socket)},
                               {"tcp_start", detail::tcp_json(c.tcp_start)},
                               {"tcp_end", detail::tcp_json(c.tcp_end)}});
    }
    std::string reason = v.invalid_reason;
    if (buffer.overflowed()) {
        if (!reason.empty())
            reason += "; ";
        reason += "capture capacity exceeded";
    }
    return {{"type", "sample"},
            {"schema", model::record_schema},
            {"sample", v.sample},
            {"batch", v.batch},
            {"role", model::name(v.role)},
            {"pid", v.pid},
            {"mode", model::name(v.config.mode)},
            {"valid", v.valid && !buffer.overflowed()},
            {"invalid_reason", reason},
            {"profile_hash", v.config.profile_hash},
            {"environment_hash", v.environment.environment_hash},
            {"config", config_json(v.config)},
            {"declaration", declaration_json(v.declaration)},
            {"environment", environment_json(v.environment)},
            {"capabilities", capabilities_json(v.capabilities)},
            {"calibration", calibration_json(v.calibration)},
            {"clock_start", clock_json(v.clock_start)},
            {"clock_end", clock_json(v.clock_end)},
            {"connections", connections},
            {"observation_level", v.observation_level},
            {"incomplete", v.incomplete},
            {"saved_context_size", v.saved_context_size},
            {"loaded_context_size", v.loaded_context_size},
            {"loaded_context_hash", v.loaded_context_hash},
            {"pinned_cpu", v.pinned_cpu},
            {"perf_complete", v.perf_complete},
            {"capture_dropped", buffer.dropped()},
            {"framework_version", model::framework_version}};
}
Json event_json(const model::SampleInfo& info, const model::Event& v) {
    const auto& s = v.snapshot;
    return {{"type", "event"},
            {"schema", model::record_schema},
            {"sample", info.sample},
            {"batch", info.batch},
            {"role", model::name(info.role)},
            {"profile_hash", info.config.profile_hash},
            {"environment_hash", info.environment.environment_hash},
            {"connection", v.connection},
            {"sequence", v.sequence},
            {"kind", model::name(v.kind)},
            {"location", model::name(v.location)},
            {"call", model::name(v.call)},
            {"call_id", v.call_id},
            {"monotonic_ns", s.monotonic_ns},
            {"thread_cpu_ns", s.thread_cpu_ns},
            {"cycles", nullable(s.cycles)},
            {"instructions", nullable(s.instructions)},
            {"perf_enabled", nullable(s.perf_enabled)},
            {"perf_running", nullable(s.perf_running)},
            {"heap", s.heap ? heap_json(*s.heap) : Json(nullptr)},
            {"requested", v.requested},
            {"transferred", v.transferred},
            {"stream_begin", v.stream_begin},
            {"stream_end", v.stream_end},
            {"result", v.result},
            {"system_error", v.system_error},
            {"raw_timestamp_ns", nullable(v.raw_timestamp_ns)},
            {"timestamp_id", nullable(v.timestamp_id)},
            {"timestamp_coverage_exact", v.timestamp_coverage_exact}};
}
} // namespace

struct Buffer::State {
    explicit State(const Limits& limits)
        : event_storage(limits.events), keylog(limits.keylog_bytes),
          plaintext(limits.bytes_per_stream), messages(limits.events) {
        if (limits.connections > std::numeric_limits<std::size_t>::max() / 2)
            throw std::length_error("too many capture connections");
        streams.reserve(limits.connections * 2);
        for (std::size_t i = 0; i < limits.connections * 2; ++i)
            streams.emplace_back(limits.bytes_per_stream);
    }
    std::vector<model::Event> event_storage;
    std::size_t event_count = 0;
    std::vector<Bytes> streams;
    Bytes keylog;
    Bytes plaintext;
    std::vector<PlaintextMessage> messages;
    std::size_t message_count = 0;
    std::size_t dropped = 0;
    bool reject() noexcept {
        ++dropped;
        return false;
    }
    std::size_t stream_index(std::size_t connection, model::Direction direction) const noexcept {
        if (connection >= streams.size() / 2)
            return streams.size();
        return connection * 2 + (direction == model::Direction::Received ? 1 : 0);
    }
};
Buffer::Buffer(const Limits& limits) : state_(std::make_unique<State>(limits)) {}
Buffer::~Buffer() = default;
bool Buffer::append(model::Event event) noexcept {
    auto& s = *state_;
    if (s.event_count == s.event_storage.size())
        return s.reject();
    s.event_storage[s.event_count++] = event;
    return true;
}
bool Buffer::append_bytes(std::size_t connection, model::Direction direction,
                          std::span<const std::uint8_t> bytes) noexcept {
    auto& s = *state_;
    auto i = s.stream_index(connection, direction);
    if (i == s.streams.size() || !s.streams[i].append(bytes))
        return s.reject();
    return true;
}
bool Buffer::append_keylog(std::string_view line) noexcept {
    auto& s = *state_;
    const bool newline = line.empty() || line.back() != '\n';
    if (!s.keylog.fits(line.size()) ||
        (newline && s.keylog.storage.size() - s.keylog.used == line.size()))
        return s.reject();
    s.keylog.append(as_bytes(line));
    if (newline)
        s.keylog.append(as_bytes("\n"));
    return true;
}
bool Buffer::append_plaintext(std::size_t connection, bool outgoing, unsigned type,
                              std::span<const std::uint8_t> bytes) noexcept {
    auto& s = *state_;
    if (connection >= s.streams.size() / 2 || s.message_count == s.messages.size() ||
        !s.plaintext.fits(bytes.size()))
        return s.reject();
    s.messages[s.message_count++] = {connection, outgoing, type, s.plaintext.used, bytes.size()};
    s.plaintext.append(bytes);
    return true;
}
std::span<const model::Event> Buffer::events() const noexcept {
    return {state_->event_storage.data(), state_->event_count};
}
std::span<const std::uint8_t> Buffer::bytes(std::size_t c, model::Direction d) const noexcept {
    const auto i = state_->stream_index(c, d);
    return i == state_->streams.size() ? std::span<const std::uint8_t>{}
                                       : state_->streams[i].view();
}
std::string_view Buffer::keylog() const noexcept {
    const auto data = state_->keylog.view();
    if (data.empty())
        return {};
    return {reinterpret_cast<const char*>(data.data()), data.size()};
}
std::span<const PlaintextMessage> Buffer::plaintext_messages() const noexcept {
    return {state_->messages.data(), state_->message_count};
}
std::span<const std::uint8_t> Buffer::plaintext_bytes() const noexcept {
    return state_->plaintext.view();
}
bool Buffer::overflowed() const noexcept {
    return state_->dropped != 0;
}
std::size_t Buffer::dropped() const noexcept {
    return state_->dropped;
}

struct Writer::State {
    State(const std::string& directory, Role role, std::size_t connections) {
        const auto prefix = directory + "/" + model::name(role);
        records = open_file(prefix + ".jsonl");
        keys = open_file(prefix + ".keys.log");
        context = open_file(prefix + ".context.bin");
        plaintext = open_file(prefix + ".plaintext.bin");
        messages = open_file(prefix + ".plaintext.jsonl");
        for (std::size_t i = 0; i < connections; ++i) {
            const auto name = prefix + ".conn-" + std::to_string(i);
            streams.push_back(open_file(name + ".sent.bin"));
            streams.push_back(open_file(name + ".received.bin"));
        }
    }
    std::ofstream records, keys, context, plaintext, messages;
    std::vector<std::ofstream> streams;
    bool written = false;
    bool context_written = false;
};
Writer::Writer(const std::string& directory, Role role, std::size_t connections)
    : state_(std::make_unique<State>(directory, role, connections)) {}
Writer::~Writer() = default;
void Writer::write(const model::SampleInfo& info, const Buffer& buffer) {
    auto& s = *state_;
    if (s.written)
        throw std::logic_error("sample artifacts already written");
    s.written = true;
    s.records << sample_json(info, buffer).dump() << '\n';
    for (const auto& event : buffer.events())
        s.records << event_json(info, event).dump() << '\n';
    s.records.flush();
    write_bytes(s.keys, as_bytes(buffer.keylog()));
    write_bytes(s.plaintext, buffer.plaintext_bytes());
    for (const auto& m : buffer.plaintext_messages()) {
        s.messages << Json({{"connection", m.connection},
                            {"outgoing", m.outgoing},
                            {"content_type", m.content_type},
                            {"offset", m.offset},
                            {"length", m.length},
                            {"location", "library_hook"}})
                          .dump()
                   << '\n';
    }
    s.messages.flush();
    for (std::size_t i = 0; i < s.streams.size(); ++i)
        write_bytes(s.streams[i], buffer.bytes(i / 2, i % 2 ? model::Direction::Received
                                                            : model::Direction::Sent));
}
void Writer::write_context(std::span<const std::uint8_t> saved) {
    if (state_->context_written)
        throw std::logic_error("context artifact already written");
    state_->context_written = true;
    write_bytes(state_->context, saved);
}
} // namespace turtle::record
