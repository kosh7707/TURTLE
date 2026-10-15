#pragma once

// Certificate lookup, Mock CA, and attempt-ledger recording declarations.
#include "model/service.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace turtle::record {

enum class ServiceArtifact { CertificateLookup, MockCa };

inline constexpr const char* attempt_ledger_type = "turtle-attempt-ledger";
inline constexpr const char* lookup_record_type = "certificate-lookup";
inline constexpr const char* ca_record_type = "mock-ca";
inline constexpr const char* attempts_filename = "attempts.jsonl";
inline constexpr const char* lookup_filename = "lookup.jsonl";
inline constexpr const char* ca_filename = "ca.jsonl";

struct ServiceEvent {
    model::ServiceEventKind kind = model::ServiceEventKind::CacheLookup;
    std::uint64_t sample = 0;
    std::size_t connection = 0;
    std::uint64_t request_id = 0;
    std::uint64_t sequence = 0;
    model::ParticipantKind participant = model::ParticipantKind::TlsClient;
    std::string_view stream_id;
    model::Snapshot snapshot;
    std::uint64_t requested = 0;
    std::uint64_t transferred = 0;
    std::int64_t result = 0;
    int system_error = 0;
};

struct ServiceConnectionInfo {
    std::uint64_t sample = 0;
    std::size_t connection = 0;
    bool warmup = false;
    std::uint64_t request_id = 0;
    model::ParticipantKind participant = model::ParticipantKind::TlsClient;
    std::string stream_id;
    std::uint64_t object_id = 0;
    std::size_t object_size = 0;
    bool cache_hit = false;
    std::uint64_t request_count = 0;
    model::DomainMemory memory;
    std::optional<model::TcpInfoSnapshot> tcp_start;
    std::optional<model::TcpInfoSnapshot> tcp_end;
    model::ArtifactStatus artifact_status = model::ArtifactStatus::Missing;
    std::string incomplete_reason;
};

// Immutable provenance copied into a service writer before measurement. The
// capacity fields describe separately reserved storage; framework_reserved_bytes
// includes ServiceBuffer::reserved_bytes() supplied by lifecycle. None of these
// values are added to the domain heap counters.
struct ServiceMetadata {
    std::uint64_t sample = 0;
    std::string scenario_name = model::lookup_scenario_name;
    model::CacheMode cache_mode = model::CacheMode::Empty;
    std::string cache_state_id;
    std::uint64_t object_id = 0;
    std::size_t object_size = 0;
    std::size_t initial_cache_bytes = 0;
    std::size_t cache_capacity = 0;
    std::size_t reference_bytes = 0;
    std::size_t reference_capacity = 0;
    std::size_t framework_reserved_bytes = 0;
    model::Mode mode = model::Mode::Timing;
    std::int64_t pid = 0;
    model::Capabilities capabilities;
    model::Calibration calibration;
    std::optional<int> pinned_cpu;
    std::string observation_level = "L0";
};

// Parent-owned ledger values exist independently of child artifacts. Deadline
// and grace values use the parent's monotonic clock domain and must not be
// synthesized from child files.
struct AttemptEntry {
    std::uint64_t attempt_id = 0;
    std::size_t requested_count = 0;
    bool started = false;
    model::AttemptStatus final_status = model::AttemptStatus::NotAttempted;
    model::FailurePhase failure_phase = model::FailurePhase::None;
    std::string reason;
    std::vector<std::string> secondary_reasons;
    std::uint64_t measurement_deadline_monotonic_ns = 0;
    unsigned flush_grace_ms = 500;
    std::vector<model::ParticipantKind> participants;
    // Parallel to artifact_status when present. Participants describe the
    // three processes and must not be used to infer the four raw artifacts.
    std::vector<std::string> artifact_names;
    std::vector<model::ArtifactStatus> artifact_status;
    std::vector<std::size_t> connections;
    std::vector<std::string> network_observation_ids;
};

struct ServiceLimits {
    std::size_t events = 32768;
    std::size_t bytes_per_direction = 1024 * 1024;
    std::size_t connections = 1;
};

// All capacity is reserved before measurement. append failure marks the
// artifact incomplete; a dropped event is never interpreted as observed zero.
class ServiceBuffer {
  public:
    explicit ServiceBuffer(const ServiceLimits& limits);
    ~ServiceBuffer();
    ServiceBuffer(const ServiceBuffer&) = delete;
    ServiceBuffer& operator=(const ServiceBuffer&) = delete;
    bool append(ServiceEvent event) noexcept;
    bool append_bytes(std::size_t connection, model::Direction direction,
                      std::span<const std::uint8_t> bytes) noexcept;
    std::span<const ServiceEvent> events() const noexcept;
    std::span<const std::uint8_t> bytes(std::size_t connection,
                                        model::Direction direction) const noexcept;
    bool overflowed() const noexcept;
    std::size_t dropped() const noexcept;
    std::size_t reserved_bytes() const noexcept;

  private:
    struct State;
    std::unique_ptr<State> state_;
};

// Writes either lookup.jsonl or ca.jsonl plus its own stream files. It does not
// emit TLS Declaration/Verification fields and never feeds service bytes to the
// TLS interpreter. Files are opened before isolation and written after measure.
class ServiceWriter {
  public:
    ServiceWriter(const std::string& sample_directory, ServiceArtifact artifact,
                  std::size_t connections, ServiceMetadata metadata);
    ~ServiceWriter();
    ServiceWriter(const ServiceWriter&) = delete;
    ServiceWriter& operator=(const ServiceWriter&) = delete;
    void write(std::span<const ServiceConnectionInfo> connections,
               const ServiceBuffer& buffer, model::ArtifactStatus footer_status,
               std::string_view incomplete_reason);

  private:
    struct State;
    std::unique_ptr<State> state_;
};

// Parent writer for attempts.jsonl. It is opened and the started row is made
// durable before child execution, so a hard-killed child cannot erase the
// requested/started denominator.
class AttemptWriter {
  public:
    AttemptWriter(const std::string& run_directory, std::size_t requested_count,
                  model::FailurePolicy policy);
    ~AttemptWriter();
    AttemptWriter(const AttemptWriter&) = delete;
    AttemptWriter& operator=(const AttemptWriter&) = delete;
    void started(const AttemptEntry& entry);
    void finished(const AttemptEntry& entry);
    void summary(std::span<const AttemptEntry> entries);

  private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace turtle::record
