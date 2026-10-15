#pragma once

// Shared value types only. This module performs no I/O or lifecycle work.
#include "turtle/adapter.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace turtle::model {

inline constexpr unsigned record_schema = 1;
// Identifies the measurement boundary semantics independently of the additive
// raw record schema. Revision 2 includes TLS key-share generation in the
// handshake window and framework return-path capture work in the I/O segment.
inline constexpr unsigned measurement_contract_revision = 2;
inline constexpr unsigned lookup_record_schema = 1;
inline constexpr unsigned attempt_ledger_schema = 1;
inline constexpr const char* framework_version = "0.1.0";
inline constexpr const char* lookup_scenario_name =
    "synthetic-lookup-plus-standard-tls";

enum class Mode { Timing, Memory, Trace };
enum class Direction { Sent, Received };
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
enum class Location { Boundary, Framework, Kernel, Hardware, Syscall, Library };
enum class Call {
    None,
    Setup,
    Open,
    Handshake,
    Verification,
    Negotiated,
    AppSend,
    AppRecv,
    Close,
    Save,
    Teardown
};
enum class EventKind {
    SetupBegin,
    SetupEnd,
    TcpReady,
    OpenBegin,
    OpenEnd,
    CallBegin,
    CallEnd,
    IoSendEnter,
    IoSendReturn,
    IoRecvEnter,
    IoRecvReturn,
    WaitBegin,
    WaitEnd,
    KernelRx,
    KernelTxSched,
    KernelTxSnd,
    KernelTxAck,
    CloseBegin,
    CloseEnd,
    Save
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

struct RunConfig {
    TlsConfig tls;
    std::string client_adapter = "openssl";
    std::string server_adapter = "openssl";
    std::string adapter_directory;
    std::string output_directory = "results/run";
    std::string profile_name = "default";
    std::string profile_hash;
    std::string profile_document;
    std::string context_directory;
    Mode mode = Mode::Timing;
    std::size_t samples = 1000;
    std::size_t warmups = 0;
    std::size_t connections = 1;
    std::uint64_t batch = 1;
    std::uint64_t seed = 1;
    unsigned timeout_ms = 10000;
    unsigned flush_grace_ms = 500;
    FailurePolicy failure_policy = FailurePolicy::FailFast;
    LookupConfig lookup;
    std::string network_manifest;
    std::optional<NetworkHandoff> network_handoff;
    std::size_t event_capacity = 32768;
    std::size_t stream_capacity = 1024 * 1024;
    std::size_t keylog_capacity = 256 * 1024;
    std::size_t calibration_samples = 64;
    bool tcp_nodelay = true;
    int socket_send_buffer = 65536;
    int socket_receive_buffer = 65536;
    bool kernel_timestamps = true;
    bool channel_observer = true;
    bool perf = true;
    bool isolate = true;
    bool pin_cores = true;
    int director_cpu = -1;
    int client_cpu = -1;
    int server_cpu = -1;
    int ca_cpu = -1;
};

struct HeapSnapshot {
    std::uint64_t live = 0;
    std::uint64_t peak = 0;
    std::uint64_t interval_peak = 0;
    std::uint64_t allocations = 0;
    std::uint64_t frees = 0;
    std::uint64_t allocated_total = 0;
};

struct Snapshot {
    std::uint64_t monotonic_ns = 0;
    std::uint64_t thread_cpu_ns = 0;
    std::optional<std::uint64_t> cycles;
    std::optional<std::uint64_t> instructions;
    std::optional<std::uint64_t> perf_enabled;
    std::optional<std::uint64_t> perf_running;
    std::optional<HeapSnapshot> heap;
};

struct Event {
    EventKind kind = EventKind::CallBegin;
    Location location = Location::Boundary;
    Call call = Call::None;
    std::uint64_t sequence = 0;
    std::uint64_t call_id = 0;
    std::size_t connection = 0;
    Snapshot snapshot;
    std::uint64_t requested = 0;
    std::uint64_t transferred = 0;
    std::uint64_t stream_begin = 0;
    std::uint64_t stream_end = 0;
    std::int64_t result = 0;
    int system_error = 0;
    // Kernel observations retain their raw clock and reported coverage. They
    // are not inserted into the boundary partition as synthetic exact events.
    std::optional<std::uint64_t> raw_timestamp_ns;
    std::optional<std::uint32_t> timestamp_id;
    bool timestamp_coverage_exact = false;
};

struct ClockPair {
    std::uint64_t monotonic_before_ns = 0;
    std::uint64_t realtime_ns = 0;
    std::uint64_t monotonic_after_ns = 0;
};

struct Environment {
    std::string kernel;
    std::string cpu_model;
    std::string compiler;
    std::string governor;
    std::string boost;
    std::string environment_hash;
    bool wsl = false;
    std::vector<int> allowed_cpus;
    std::vector<int> physical_cpus;
    double load_before = 0;
    std::vector<std::string> warnings;
};

struct Capabilities {
    bool monotonic_clock = false;
    bool thread_cpu_clock = false;
    bool perf = false;
    bool heap_tracking = false;
    bool stack_tracking = false;
    bool kernel_timestamp_configured = false;
    bool hardware_timestamps = false;
    bool affinity = false;
    std::uint64_t monotonic_resolution_ns = 0;
    std::uint64_t thread_cpu_resolution_ns = 0;
    std::string perf_note;
    std::string stack_note;
    std::string hardware_note;
    std::string trace_note;
    std::vector<std::string> warnings;
};

struct Calibration {
    std::vector<std::uint64_t> elapsed_ns;
    std::vector<std::uint64_t> cpu_ns;
    std::vector<std::uint64_t> cycles;
    std::vector<std::uint64_t> instructions;
};

struct SocketSettings {
    bool nonblocking = false;
    bool tcp_nodelay = false;
    int send_buffer = 0;
    int receive_buffer = 0;
    bool kernel_timestamps = false;
};

// A disengaged field is unsupported or was not collected; it is never an
// observed zero. `structure_bytes` is the TCP_INFO length returned by Linux.
// `note` explains a missing snapshot or fields unavailable at that length.
struct TcpInfoSnapshot {
    std::size_t structure_bytes = 0;
    std::optional<std::uint8_t> state;
    std::optional<std::uint8_t> retransmits;
    std::optional<std::uint32_t> retrans;
    std::optional<std::uint32_t> total_retrans;
    std::optional<std::uint32_t> unacked;
    std::optional<std::uint32_t> lost;
    std::optional<std::uint32_t> snd_mss;
    std::optional<std::uint32_t> rcv_mss;
    std::optional<std::uint32_t> segs_out;
    std::optional<std::uint32_t> segs_in;
    std::optional<std::uint32_t> data_segs_out;
    std::optional<std::uint32_t> data_segs_in;
    std::optional<std::uint64_t> bytes_acked;
    std::optional<std::uint64_t> bytes_received;
    std::string note;
};

struct DomainMemory {
    HeapDomain domain = HeapDomain::Tls;
    std::optional<HeapSnapshot> heap;
    std::size_t logical_cache_bytes = 0;
    std::size_t cache_capacity = 0;
    std::size_t reference_bytes = 0;
    std::size_t framework_reserved_bytes = 0;
};

struct ConnectionInfo {
    std::size_t index = 0;
    bool warmup = false;
    Verification verification = Verification::Failed;
    Negotiated negotiated;
    bool application_verified = false;
    // The primary measurement start is absent when its observation boundary
    // cannot be seen (not an observed sequence zero).
    std::optional<std::uint64_t> start_sequence;
    std::uint64_t end_sequence = 0;
    bool primary_window_available = false;
    std::string primary_window_reason = "measurement_boundaries_incomplete";
    std::optional<SocketSettings> socket;
    std::optional<TcpInfoSnapshot> tcp_start;
    std::optional<TcpInfoSnapshot> tcp_end;
};

struct SampleInfo {
    std::uint64_t sample = 0;
    std::uint64_t batch = 1;
    Role role = Role::Client;
    std::int64_t pid = 0;
    RunConfig config;
    Declaration declaration;
    Environment environment;
    Capabilities capabilities;
    Calibration calibration;
    ClockPair clock_start;
    ClockPair clock_end;
    std::vector<ConnectionInfo> connections;
    bool valid = true;
    bool tls_stream_available = true;
    bool io_events_available = true;
    bool kernel_receive_events_available = false;
    std::string invalid_reason;
    std::string observation_level = "L0";
    std::string tls_stream_reason;
    std::string io_events_reason;
    std::string kernel_receive_events_reason = "kernel_timestamps_not_configured";
    std::vector<std::string> incomplete;
    std::size_t saved_context_size = 0;
    std::size_t loaded_context_size = 0;
    std::string loaded_context_hash;
    int pinned_cpu = -1;
    bool perf_complete = false;
};

const char* name(Role value) noexcept;
const char* name(Mode value) noexcept;
const char* name(Direction value) noexcept;
const char* name(ParticipantKind value) noexcept;
const char* name(CacheMode value) noexcept;
const char* name(FailurePolicy value) noexcept;
const char* name(AttemptStatus value) noexcept;
const char* name(FailurePhase value) noexcept;
const char* name(ArtifactStatus value) noexcept;
const char* name(HeapDomain value) noexcept;
const char* name(ServiceEventKind value) noexcept;
const char* name(Location value) noexcept;
const char* name(Call value) noexcept;
const char* name(EventKind value) noexcept;
const char* name(Verification value) noexcept;
const char* name(Step value) noexcept;
std::string fingerprint(const std::string& text);
std::uint64_t fnv1a64(std::span<const std::uint8_t> bytes) noexcept;
std::string fingerprint(std::span<const std::uint8_t> bytes);
const char* build_information() noexcept;

} // namespace turtle::model
