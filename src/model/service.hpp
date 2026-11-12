#pragma once

// Certificate lookup and Mock CA value types.
#include "model/model.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace turtle::model {

inline constexpr unsigned lookup_record_schema = 1;
inline constexpr const char* lookup_scenario_name = "synthetic-lookup-plus-standard-tls";

enum class ParticipantKind { TlsClient, TlsServer, MockCa };
enum class CacheMode { Empty, FixedSnapshot };
enum class ArtifactStatus { Complete, Partial, Missing };
enum class HeapDomain { Tls, Lookup, MockCa };
enum class ServiceEventKind {
    CacheLookup,
    CacheHit,
    CacheMiss,
    CacheInsert,
    RequestBegin,
    ResponseComplete,
    UsableObject,
    ScenarioBegin,
    ScenarioEnd,
    CaProcessBegin,
    CaProcessEnd,
    IoSendEnter,
    IoSendReturn,
    IoRecvEnter,
    IoRecvReturn,
    WaitBegin,
    WaitEnd
};

// Profile input for the explicit certificate lookup followed by stock TLS.
// Paths are resolved by config relative to the profile before RunConfig is
// handed to lifecycle. An empty snapshot_file means JSON null/not supplied.
struct LookupConfig {
    std::string address = "127.0.0.1";
    std::string source_address = "0.0.0.0";
    std::uint16_t port = 44332;
    std::uint16_t control_port = 44333;
    bool enabled = false;
    std::string object_file;
    CacheMode cache_mode = CacheMode::Empty;
    std::string snapshot_file;
};

// Optional local experiment provenance, without namespace or process ownership.
struct NetworkHandoff {
    std::string net_profile_document;
    std::string provenance_file;
    std::string observations_file;
};

struct DomainMemory {
    HeapDomain domain = HeapDomain::Tls;
    std::optional<HeapSnapshot> heap;
    std::size_t logical_cache_bytes = 0;
    std::size_t cache_capacity = 0;
    std::size_t reference_bytes = 0;
    std::size_t framework_reserved_bytes = 0;
};

const char* name(ParticipantKind value) noexcept;
const char* name(CacheMode value) noexcept;
const char* name(ArtifactStatus value) noexcept;
const char* name(HeapDomain value) noexcept;
const char* name(ServiceEventKind value) noexcept;

} // namespace turtle::model
