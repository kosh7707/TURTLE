#pragma once

// Certificate lookup, Mock CA, and attempt-ledger value types.
#include "model/model.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace turtle::model {

inline constexpr unsigned lookup_record_schema = 1;
inline constexpr unsigned attempt_ledger_schema = 1;
inline constexpr const char* lookup_scenario_name =
    "synthetic-lookup-plus-standard-tls";

enum class ParticipantKind { TlsClient, TlsServer, MockCa };
enum class CacheMode { Empty, FixedSnapshot };
enum class FailurePolicy { FailFast, FixedAttempts };
enum class AttemptStatus { NotAttempted, Success, Timeout, Error, Incomplete };
enum class FailurePhase { None, Startup, Listener, TcpReady, Scenario, Flush, Exit };
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
    bool enabled = false;
    std::string object_file;
    CacheMode cache_mode = CacheMode::Empty;
    std::string snapshot_file;
};

// Parsed C3 manifest handoff. File descriptors are borrowed copies inherited
// from the Python coordinator. The director/roles close only their copies and
// never receive the router namespace fd.
struct NetworkHandoff {
    int client_namespace_fd = -1;
    int server_namespace_fd = -1;
    int ca_namespace_fd = -1;
    int phase_control_fd = -1;
    std::string client_tls_address;
    std::string server_address;
    std::string client_ca_address;
    std::string ca_address;
    std::string client_tls_interface;
    std::string server_interface;
    std::string client_ca_interface;
    std::string ca_interface;
    std::string router_client_tls_interface;
    std::string router_server_interface;
    std::string router_client_ca_interface;
    std::string router_ca_interface;
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
const char* name(FailurePolicy value) noexcept;
const char* name(AttemptStatus value) noexcept;
const char* name(FailurePhase value) noexcept;
const char* name(ArtifactStatus value) noexcept;
const char* name(HeapDomain value) noexcept;
const char* name(ServiceEventKind value) noexcept;

} // namespace turtle::model
